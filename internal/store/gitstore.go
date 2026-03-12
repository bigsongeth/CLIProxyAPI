package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// gcInterval defines minimum time between garbage collection runs.
const gcInterval = 5 * time.Minute

// GitTokenStore persists token records and auth metadata using git as the backing storage.
type GitTokenStore struct {
	mu            sync.Mutex
	dirLock       sync.RWMutex
	activeAuthDir string
	repoAuthDir   string
	repoDir       string
	configDir     string
	remote        string
	username      string
	password      string
	lastGC        time.Time
}

// NewGitTokenStore creates a token store that saves credentials to disk through the
// TokenStorage implementation embedded in the token record.
func NewGitTokenStore(remote, username, password string) *GitTokenStore {
	return &GitTokenStore{
		remote:   remote,
		username: username,
		password: password,
	}
}

// SetBaseDir updates the active local auth directory used by the application.
func (s *GitTokenStore) SetBaseDir(dir string) {
	clean := strings.TrimSpace(dir)
	s.dirLock.Lock()
	defer s.dirLock.Unlock()
	if clean == "" {
		s.activeAuthDir = ""
		return
	}
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	s.activeAuthDir = clean
}

// SetRepositoryRoot configures the git repository workspace and mirror directories.
func (s *GitTokenStore) SetRepositoryRoot(root string) {
	clean := strings.TrimSpace(root)
	s.dirLock.Lock()
	defer s.dirLock.Unlock()
	if clean == "" {
		s.repoDir = ""
		s.repoAuthDir = ""
		s.configDir = ""
		return
	}
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	s.repoDir = clean
	s.repoAuthDir = filepath.Join(clean, "auths")
	s.configDir = filepath.Join(clean, "config")
}

// AuthDir returns the active local auth directory.
func (s *GitTokenStore) AuthDir() string {
	return s.activeAuthDirSnapshot()
}

// ConfigPath returns the managed config file path.
func (s *GitTokenStore) ConfigPath() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	if s.configDir == "" {
		return ""
	}
	return filepath.Join(s.configDir, "config.yaml")
}

// EnsureRepository prepares the local git working tree by cloning or opening the repository.
func (s *GitTokenStore) EnsureRepository() error {
	s.dirLock.Lock()
	if s.remote == "" {
		s.dirLock.Unlock()
		return fmt.Errorf("git token store: remote not configured")
	}
	if s.repoDir == "" {
		s.dirLock.Unlock()
		return fmt.Errorf("git token store: repository path not configured")
	}
	if s.repoAuthDir == "" {
		s.repoAuthDir = filepath.Join(s.repoDir, "auths")
	}
	if s.configDir == "" {
		s.configDir = filepath.Join(s.repoDir, "config")
	}
	repoDir := s.repoDir
	repoAuthDir := s.repoAuthDir
	configDir := s.configDir
	activeAuthDir := s.activeAuthDir
	gitDir := filepath.Join(repoDir, ".git")
	authMethod := s.gitAuth()
	var initPaths []string
	if _, err := os.Stat(gitDir); errors.Is(err, fs.ErrNotExist) {
		if errMk := os.MkdirAll(repoDir, 0o700); errMk != nil {
			s.dirLock.Unlock()
			return fmt.Errorf("git token store: create repo dir: %w", errMk)
		}
		if _, errClone := git.PlainClone(repoDir, &git.CloneOptions{Auth: authMethod, URL: s.remote, Depth: 1}); errClone != nil {
			if errors.Is(errClone, transport.ErrEmptyRemoteRepository) {
				_ = os.RemoveAll(gitDir)
				repo, errInit := git.PlainInit(repoDir, false)
				if errInit != nil {
					s.dirLock.Unlock()
					return fmt.Errorf("git token store: init empty repo: %w", errInit)
				}
				if _, errRemote := repo.Remote("origin"); errRemote != nil {
					if _, errCreate := repo.CreateRemote(&config.RemoteConfig{
						Name: "origin",
						URLs: []string{s.remote},
					}); errCreate != nil && !errors.Is(errCreate, git.ErrRemoteExists) {
						s.dirLock.Unlock()
						return fmt.Errorf("git token store: configure remote: %w", errCreate)
					}
				}
				if err := os.MkdirAll(repoAuthDir, 0o700); err != nil {
					s.dirLock.Unlock()
					return fmt.Errorf("git token store: create repo auth dir: %w", err)
				}
				if err := os.MkdirAll(configDir, 0o700); err != nil {
					s.dirLock.Unlock()
					return fmt.Errorf("git token store: create config dir: %w", err)
				}
				if err := ensureEmptyFile(filepath.Join(repoAuthDir, ".gitkeep")); err != nil {
					s.dirLock.Unlock()
					return fmt.Errorf("git token store: create auth placeholder: %w", err)
				}
				if err := ensureEmptyFile(filepath.Join(configDir, ".gitkeep")); err != nil {
					s.dirLock.Unlock()
					return fmt.Errorf("git token store: create config placeholder: %w", err)
				}
				initPaths = []string{
					filepath.Join("auths", ".gitkeep"),
					filepath.Join("config", ".gitkeep"),
				}
			} else {
				s.dirLock.Unlock()
				return fmt.Errorf("git token store: clone remote: %w", errClone)
			}
		}
	} else if err != nil {
		s.dirLock.Unlock()
		return fmt.Errorf("git token store: stat repo: %w", err)
	} else {
		repo, errOpen := git.PlainOpen(repoDir)
		if errOpen != nil {
			s.dirLock.Unlock()
			return fmt.Errorf("git token store: open repo: %w", errOpen)
		}
		worktree, errWorktree := repo.Worktree()
		if errWorktree != nil {
			s.dirLock.Unlock()
			return fmt.Errorf("git token store: worktree: %w", errWorktree)
		}
		if errPull := worktree.Pull(&git.PullOptions{Auth: authMethod, RemoteName: "origin", Depth: 1}); errPull != nil {
			switch {
			case errors.Is(errPull, git.NoErrAlreadyUpToDate),
				errors.Is(errPull, git.ErrUnstagedChanges),
				errors.Is(errPull, git.ErrNonFastForwardUpdate):
				// Ignore clean syncs, local edits, and remote divergence—local changes win.
			case errors.Is(errPull, transport.ErrAuthenticationRequired),
				errors.Is(errPull, plumbing.ErrReferenceNotFound),
				errors.Is(errPull, transport.ErrEmptyRemoteRepository):
				// Ignore authentication prompts and empty remote references on initial sync.
			default:
				s.dirLock.Unlock()
				return fmt.Errorf("git token store: pull: %w", errPull)
			}
		}
	}
	if err := os.MkdirAll(repoAuthDir, 0o700); err != nil {
		s.dirLock.Unlock()
		return fmt.Errorf("git token store: create repo auth dir: %w", err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		s.dirLock.Unlock()
		return fmt.Errorf("git token store: create config dir: %w", err)
	}
	if strings.TrimSpace(activeAuthDir) != "" {
		if err := os.MkdirAll(activeAuthDir, 0o700); err != nil {
			s.dirLock.Unlock()
			return fmt.Errorf("git token store: create active auth dir: %w", err)
		}
	}
	s.dirLock.Unlock()
	if len(initPaths) > 0 {
		s.mu.Lock()
		err := s.commitAndPushLocked("Initialize git token store", initPaths...)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// ImportLegacyAuthDir seeds the repository mirror from the active auth directory when needed.
func (s *GitTokenStore) ImportLegacyAuthDir() error {
	if err := s.EnsureRepository(); err != nil {
		return err
	}

	activeDir := s.activeAuthDirSnapshot()
	if activeDir == "" {
		return nil
	}
	if _, errStat := os.Stat(activeDir); errStat != nil {
		if errors.Is(errStat, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("git token store: stat active auth dir: %w", errStat)
	}

	repoAuthDir := s.repoAuthDirSnapshot()
	if repoAuthDir == "" {
		return fmt.Errorf("git token store: repo auth dir not configured")
	}
	if hasAuths, errHasAuths := hasJSONFiles(repoAuthDir); errHasAuths != nil {
		return errHasAuths
	} else if hasAuths {
		return nil
	}

	imported, errImport := s.copyAuthFiles(activeDir, repoAuthDir)
	if errImport != nil {
		return errImport
	}
	if len(imported) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitAndPushLocked("Seed auth mirror", imported...)
}

// Save persists token storage and metadata to the resolved auth file path.
func (s *GitTokenStore) Save(_ context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth filestore: auth is nil")
	}

	path, err := s.resolveAuthPath(auth)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("auth filestore: missing file path attribute for %s", auth.ID)
	}

	if auth.Disabled {
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return "", nil
		}
	}

	if err = s.EnsureRepository(); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("auth filestore: create dir failed: %w", err)
	}

	switch {
	case auth.Storage != nil:
		if err = auth.Storage.SaveTokenToFile(path); err != nil {
			return "", err
		}
	case auth.Metadata != nil:
		raw, errMarshal := json.Marshal(auth.Metadata)
		if errMarshal != nil {
			return "", fmt.Errorf("auth filestore: marshal metadata failed: %w", errMarshal)
		}
		if existing, errRead := os.ReadFile(path); errRead == nil {
			if jsonEqual(existing, raw) {
				return path, nil
			}
		} else if !os.IsNotExist(errRead) {
			return "", fmt.Errorf("auth filestore: read existing failed: %w", errRead)
		}
		tmp := path + ".tmp"
		if errWrite := os.WriteFile(tmp, raw, 0o600); errWrite != nil {
			return "", fmt.Errorf("auth filestore: write temp failed: %w", errWrite)
		}
		if errRename := os.Rename(tmp, path); errRename != nil {
			return "", fmt.Errorf("auth filestore: rename failed: %w", errRename)
		}
	default:
		return "", fmt.Errorf("auth filestore: nothing to persist for %s", auth.ID)
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["path"] = path

	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}

	relPath, errSync := s.syncActivePathToRepoLocked(path)
	if errSync != nil {
		return "", errSync
	}
	messageID := auth.ID
	if strings.TrimSpace(messageID) == "" {
		messageID = filepath.Base(path)
	}
	if errCommit := s.commitAndPushLocked(fmt.Sprintf("Update auth %s", strings.TrimSpace(messageID)), relPath); errCommit != nil {
		return "", errCommit
	}

	return path, nil
}

// List enumerates all auth JSON files under the active directory.
func (s *GitTokenStore) List(_ context.Context) ([]*cliproxyauth.Auth, error) {
	if err := s.EnsureRepository(); err != nil {
		return nil, err
	}
	dir := s.activeAuthDirSnapshot()
	if dir == "" {
		return nil, fmt.Errorf("auth filestore: directory not configured")
	}
	entries := make([]*cliproxyauth.Auth, 0)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		auth, err := s.readAuthFile(path, dir)
		if err != nil {
			return nil
		}
		if auth != nil {
			entries = append(entries, auth)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// Delete removes the auth file.
func (s *GitTokenStore) Delete(_ context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("auth filestore: id is empty")
	}
	path, err := s.resolveDeletePath(id)
	if err != nil {
		return err
	}
	if err = s.EnsureRepository(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("auth filestore: delete failed: %w", err)
	}
	rel, errMirror := s.removeRepoMirrorForActivePathLocked(path)
	if errMirror != nil {
		return errMirror
	}
	if rel == "" {
		return nil
	}
	messageID := id
	if errCommit := s.commitAndPushLocked(fmt.Sprintf("Delete auth %s", messageID), rel); errCommit != nil {
		return errCommit
	}
	return nil
}

// PersistAuthFiles commits and pushes auth changes after mirroring active auth paths into the repository.
func (s *GitTokenStore) PersistAuthFiles(_ context.Context, message string, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	if err := s.EnsureRepository(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		rel, ok, err := s.prepareRepoPathLocked(p)
		if err != nil {
			return err
		}
		if ok {
			filtered = append(filtered, rel)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	if strings.TrimSpace(message) == "" {
		message = "Sync watcher updates"
	}
	return s.commitAndPushLocked(message, filtered...)
}

func (s *GitTokenStore) resolveDeletePath(id string) (string, error) {
	if strings.ContainsRune(id, os.PathSeparator) || filepath.IsAbs(id) {
		return s.resolveAgainstActiveDir(id), nil
	}
	dir := s.activeAuthDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("auth filestore: directory not configured")
	}
	return filepath.Join(dir, id), nil
}

func (s *GitTokenStore) readAuthFile(path, baseDir string) (*cliproxyauth.Auth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	metadata := make(map[string]any)
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal auth json: %w", err)
	}
	provider, _ := metadata["type"].(string)
	if provider == "" {
		provider = "unknown"
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	id := s.idFor(path, baseDir)
	auth := &cliproxyauth.Auth{
		ID:               id,
		Provider:         provider,
		FileName:         id,
		Label:            s.labelFor(metadata),
		Status:           cliproxyauth.StatusActive,
		Attributes:       map[string]string{"path": path},
		Metadata:         metadata,
		CreatedAt:        info.ModTime(),
		UpdatedAt:        info.ModTime(),
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}
	if email, ok := metadata["email"].(string); ok && email != "" {
		auth.Attributes["email"] = email
	}
	return auth, nil
}

func (s *GitTokenStore) idFor(path, baseDir string) string {
	if baseDir == "" {
		return path
	}
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return path
	}
	return rel
}

func (s *GitTokenStore) resolveAuthPath(auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth filestore: auth is nil")
	}
	if auth.Attributes != nil {
		if p := strings.TrimSpace(auth.Attributes["path"]); p != "" {
			return s.resolveAgainstActiveDir(p), nil
		}
	}
	if fileName := strings.TrimSpace(auth.FileName); fileName != "" {
		if filepath.IsAbs(fileName) {
			return fileName, nil
		}
		if dir := s.activeAuthDirSnapshot(); dir != "" {
			return filepath.Join(dir, fileName), nil
		}
		return fileName, nil
	}
	if auth.ID == "" {
		return "", fmt.Errorf("auth filestore: missing id")
	}
	if filepath.IsAbs(auth.ID) {
		return auth.ID, nil
	}
	dir := s.activeAuthDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("auth filestore: directory not configured")
	}
	return filepath.Join(dir, auth.ID), nil
}

func (s *GitTokenStore) labelFor(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata["label"].(string); ok && v != "" {
		return v
	}
	if v, ok := metadata["email"].(string); ok && v != "" {
		return v
	}
	if project, ok := metadata["project_id"].(string); ok && project != "" {
		return project
	}
	return ""
}

func (s *GitTokenStore) activeAuthDirSnapshot() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	return s.activeAuthDir
}

func (s *GitTokenStore) repoAuthDirSnapshot() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	return s.repoAuthDir
}

func (s *GitTokenStore) repoDirSnapshot() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	return s.repoDir
}

func (s *GitTokenStore) gitAuth() transport.AuthMethod {
	if s.username == "" && s.password == "" {
		return nil
	}
	user := s.username
	if user == "" {
		user = "git"
	}
	return &http.BasicAuth{Username: user, Password: s.password}
}

func (s *GitTokenStore) relativeToRepo(path string) (string, error) {
	repoDir := s.repoDirSnapshot()
	if repoDir == "" {
		return "", fmt.Errorf("git token store: repository path not configured")
	}
	absRepo := repoDir
	if abs, err := filepath.Abs(repoDir); err == nil {
		absRepo = abs
	}
	cleanPath := path
	if abs, err := filepath.Abs(path); err == nil {
		cleanPath = abs
	}
	rel, err := filepath.Rel(absRepo, cleanPath)
	if err != nil {
		return "", fmt.Errorf("git token store: relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("git token store: path outside repository")
	}
	return rel, nil
}

func (s *GitTokenStore) commitAndPushLocked(message string, relPaths ...string) error {
	repoDir := s.repoDirSnapshot()
	if repoDir == "" {
		return fmt.Errorf("git token store: repository path not configured")
	}
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("git token store: open repo: %w", err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("git token store: worktree: %w", err)
	}
	added := false
	for _, rel := range relPaths {
		if strings.TrimSpace(rel) == "" {
			continue
		}
		if _, err = worktree.Add(rel); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if _, errRemove := worktree.Remove(rel); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
					return fmt.Errorf("git token store: remove %s: %w", rel, errRemove)
				}
			} else {
				return fmt.Errorf("git token store: add %s: %w", rel, err)
			}
		}
		added = true
	}
	if !added {
		return nil
	}
	status, err := worktree.Status()
	if err != nil {
		return fmt.Errorf("git token store: status: %w", err)
	}
	if status.IsClean() {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		message = "Update auth store"
	}
	signature := &object.Signature{
		Name:  "CLIProxyAPI",
		Email: "cliproxy@local",
		When:  time.Now(),
	}
	commitHash, err := worktree.Commit(message, &git.CommitOptions{
		Author: signature,
	})
	if err != nil {
		if errors.Is(err, git.ErrEmptyCommit) {
			return nil
		}
		return fmt.Errorf("git token store: commit: %w", err)
	}
	headRef, errHead := repo.Head()
	if errHead != nil {
		if !errors.Is(errHead, plumbing.ErrReferenceNotFound) {
			return fmt.Errorf("git token store: get head: %w", errHead)
		}
	} else if errRewrite := s.rewriteHeadAsSingleCommit(repo, headRef.Name(), commitHash, message, signature); errRewrite != nil {
		return errRewrite
	}
	s.maybeRunGC(repo)
	if err = repo.Push(&git.PushOptions{Auth: s.gitAuth(), Force: true}); err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil
		}
		return fmt.Errorf("git token store: push: %w", err)
	}
	return nil
}

// rewriteHeadAsSingleCommit rewrites the current branch tip to a single-parentless commit and leaves history squashed.
func (s *GitTokenStore) rewriteHeadAsSingleCommit(repo *git.Repository, branch plumbing.ReferenceName, commitHash plumbing.Hash, message string, signature *object.Signature) error {
	commitObj, err := repo.CommitObject(commitHash)
	if err != nil {
		return fmt.Errorf("git token store: inspect head commit: %w", err)
	}
	squashed := &object.Commit{
		Author:       *signature,
		Committer:    *signature,
		Message:      message,
		TreeHash:     commitObj.TreeHash,
		ParentHashes: nil,
		Encoding:     commitObj.Encoding,
		ExtraHeaders: commitObj.ExtraHeaders,
	}
	mem := &plumbing.MemoryObject{}
	mem.SetType(plumbing.CommitObject)
	if err := squashed.Encode(mem); err != nil {
		return fmt.Errorf("git token store: encode squashed commit: %w", err)
	}
	newHash, err := repo.Storer.SetEncodedObject(mem)
	if err != nil {
		return fmt.Errorf("git token store: write squashed commit: %w", err)
	}
	if err := repo.Storer.SetReference(plumbing.NewHashReference(branch, newHash)); err != nil {
		return fmt.Errorf("git token store: update branch reference: %w", err)
	}
	return nil
}

func (s *GitTokenStore) maybeRunGC(repo *git.Repository) {
	now := time.Now()
	if now.Sub(s.lastGC) < gcInterval {
		return
	}
	s.lastGC = now

	pruneOpts := git.PruneOptions{
		OnlyObjectsOlderThan: now,
		Handler:              repo.DeleteObject,
	}
	if err := repo.Prune(pruneOpts); err != nil && !errors.Is(err, git.ErrLooseObjectsNotSupported) {
		return
	}
	_ = repo.RepackObjects(&git.RepackConfig{})
}

// PersistConfig implements the watcher persister interface.
// GitTokenStore intentionally does not persist config changes; only auths are mirrored.
func (s *GitTokenStore) PersistConfig(_ context.Context) error {
	return nil
}

func (s *GitTokenStore) resolveAgainstActiveDir(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || filepath.IsAbs(trimmed) {
		return trimmed
	}
	if dir := s.activeAuthDirSnapshot(); dir != "" {
		return filepath.Join(dir, trimmed)
	}
	return trimmed
}

func (s *GitTokenStore) prepareRepoPathLocked(path string) (string, bool, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", false, nil
	}
	absPath := trimmed
	if !filepath.IsAbs(absPath) {
		absPath = s.resolveAgainstActiveDir(absPath)
		if abs, err := filepath.Abs(absPath); err == nil {
			absPath = abs
		}
	}
	if rel, ok, err := s.mirrorActivePathToRepoLocked(absPath); ok || err != nil {
		return rel, ok, err
	}
	if rel, ok, err := s.stageRepoPathLocked(absPath); ok || err != nil {
		return rel, ok, err
	}
	return "", false, fmt.Errorf("git token store: auth path outside active and repo auth directories: %s", trimmed)
}

func (s *GitTokenStore) syncActivePathToRepoLocked(activePath string) (string, error) {
	rel, ok, err := s.mirrorActivePathToRepoLocked(activePath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("git token store: active auth path outside configured auth directory: %s", activePath)
	}
	return rel, nil
}

func (s *GitTokenStore) removeRepoMirrorForActivePathLocked(activePath string) (string, error) {
	repoPath, ok, err := s.mapActivePathToRepoPath(activePath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("git token store: active auth path outside configured auth directory: %s", activePath)
	}
	if err := os.Remove(repoPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("git token store: delete repo auth mirror: %w", err)
	}
	return s.relativeToRepo(repoPath)
}

func (s *GitTokenStore) mirrorActivePathToRepoLocked(activePath string) (string, bool, error) {
	repoPath, ok, err := s.mapActivePathToRepoPath(activePath)
	if err != nil || !ok {
		return "", ok, err
	}
	if _, statErr := os.Stat(activePath); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			rel, errRemove := s.removeRepoMirrorForActivePathLocked(activePath)
			return rel, true, errRemove
		}
		return "", true, fmt.Errorf("git token store: stat active auth file: %w", statErr)
	}
	if err := copyFileBytes(activePath, repoPath); err != nil {
		return "", true, err
	}
	rel, err := s.relativeToRepo(repoPath)
	return rel, true, err
}

func (s *GitTokenStore) stageRepoPathLocked(path string) (string, bool, error) {
	repoAuthDir := s.repoAuthDirSnapshot()
	if repoAuthDir == "" {
		return "", false, fmt.Errorf("git token store: repo auth dir not configured")
	}
	absRepoAuthDir, err := filepath.Abs(repoAuthDir)
	if err != nil {
		return "", false, fmt.Errorf("git token store: resolve repo auth dir: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false, fmt.Errorf("git token store: resolve repo auth path: %w", err)
	}
	relToAuthDir, err := filepath.Rel(absRepoAuthDir, absPath)
	if err != nil {
		return "", false, fmt.Errorf("git token store: relative repo auth path: %w", err)
	}
	if relToAuthDir == ".." || strings.HasPrefix(relToAuthDir, ".."+string(os.PathSeparator)) {
		return "", false, nil
	}
	rel, err := s.relativeToRepo(absPath)
	if err != nil {
		return "", true, err
	}
	return rel, true, nil
}

func (s *GitTokenStore) mapActivePathToRepoPath(activePath string) (string, bool, error) {
	activeAuthDir := s.activeAuthDirSnapshot()
	repoAuthDir := s.repoAuthDirSnapshot()
	if activeAuthDir == "" {
		return "", false, fmt.Errorf("git token store: active auth dir not configured")
	}
	if repoAuthDir == "" {
		return "", false, fmt.Errorf("git token store: repo auth dir not configured")
	}
	absActiveDir, err := filepath.Abs(activeAuthDir)
	if err != nil {
		return "", false, fmt.Errorf("git token store: resolve active auth dir: %w", err)
	}
	absRepoAuthDir, err := filepath.Abs(repoAuthDir)
	if err != nil {
		return "", false, fmt.Errorf("git token store: resolve repo auth dir: %w", err)
	}
	absPath, err := filepath.Abs(activePath)
	if err != nil {
		return "", false, fmt.Errorf("git token store: resolve active auth path: %w", err)
	}
	rel, err := filepath.Rel(absActiveDir, absPath)
	if err != nil {
		return "", false, fmt.Errorf("git token store: relative active auth path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false, nil
	}
	return filepath.Join(absRepoAuthDir, rel), true, nil
}

func ensureEmptyFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return os.WriteFile(path, []byte{}, 0o600)
		}
		return err
	}
	return nil
}

func hasJSONFiles(dir string) (bool, error) {
	if strings.TrimSpace(dir) == "" {
		return false, nil
	}
	found := false
	errWalk := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if errors.Is(errWalk, filepath.SkipAll) {
		return true, nil
	}
	if errWalk != nil {
		return false, fmt.Errorf("git token store: inspect auth dir: %w", errWalk)
	}
	return found, nil
}

func (s *GitTokenStore) copyAuthFiles(srcDir, destDir string) ([]string, error) {
	imported := make([]string, 0)
	errWalk := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		info, errInfo := d.Info()
		if errInfo != nil {
			return errInfo
		}
		if info.Size() == 0 {
			return nil
		}
		rel, errRel := filepath.Rel(srcDir, path)
		if errRel != nil {
			return errRel
		}
		dest := filepath.Join(destDir, rel)
		if err := copyFileBytes(path, dest); err != nil {
			return err
		}
		relDest, errDestRel := s.relativeToRepo(dest)
		if errDestRel != nil {
			return errDestRel
		}
		imported = append(imported, relDest)
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("git token store: seed auth mirror: %w", errWalk)
	}
	return imported, nil
}

func copyFileBytes(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("git token store: read source auth file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("git token store: create repo auth directory: %w", err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return fmt.Errorf("git token store: write repo auth file: %w", err)
	}
	return nil
}

func jsonEqual(a, b []byte) bool {
	var objA any
	var objB any
	if err := json.Unmarshal(a, &objA); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &objB); err != nil {
		return false
	}
	return deepEqualJSON(objA, objB)
}

func deepEqualJSON(a, b any) bool {
	switch valA := a.(type) {
	case map[string]any:
		valB, ok := b.(map[string]any)
		if !ok || len(valA) != len(valB) {
			return false
		}
		for key, subA := range valA {
			subB, ok1 := valB[key]
			if !ok1 || !deepEqualJSON(subA, subB) {
				return false
			}
		}
		return true
	case []any:
		sliceB, ok := b.([]any)
		if !ok || len(valA) != len(sliceB) {
			return false
		}
		for i := range valA {
			if !deepEqualJSON(valA[i], sliceB[i]) {
				return false
			}
		}
		return true
	case float64:
		valB, ok := b.(float64)
		if !ok {
			return false
		}
		return valA == valB
	case string:
		valB, ok := b.(string)
		if !ok {
			return false
		}
		return valA == valB
	case bool:
		valB, ok := b.(bool)
		if !ok {
			return false
		}
		return valA == valB
	case nil:
		return b == nil
	default:
		return false
	}
}
