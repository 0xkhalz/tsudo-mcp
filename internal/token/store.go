package token

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	envTokenFile  = "TSUDO_MCP_TOKEN_FILE"
	envRuntimeDir = "XDG_RUNTIME_DIR"
	maxTokenBytes = 1 << 20
)

var (
	// ErrNotFound indicates the token file does not exist.
	ErrNotFound = errors.New("token file not found")
	// ErrInvalidPermissions indicates the token file is not a regular 0600 file.
	ErrInvalidPermissions = errors.New("token file has invalid permissions or type")
	// ErrInvalidOwner indicates the token file is not owned by the current UID.
	ErrInvalidOwner = errors.New("token file has invalid owner")
	// ErrEmptyToken indicates the token file exists but contains no token.
	ErrEmptyToken = errors.New("token file is empty")
	// ErrTokenNotFoundInOutput indicates no valid token was found in tsudo output.
	ErrTokenNotFoundInOutput = errors.New("tsudo token not found in output")
)

// Info describes the filesystem metadata and validation state of a token file.
type Info struct {
	Path    string
	Exists  bool
	Mode    fs.FileMode
	UID     uint32
	ModTime time.Time
	Valid   bool
	Err     error
}

// Store manages persistence and inspection of the tsudo token.
type Store interface {
	Read() (string, error)
	Write(tok string) error
	Clear() error
	Stat() (Info, error)
	Path() string
}

// DefaultPath resolves the token file path from TSUDO_MCP_TOKEN_FILE or XDG_RUNTIME_DIR.
func DefaultPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(envTokenFile)); p != "" {
		return p, nil
	}
	xdg := strings.TrimSpace(os.Getenv(envRuntimeDir))
	if xdg == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set")
	}
	return filepath.Join(xdg, "tsudo-token"), nil
}

// FileStore is a fail-closed filesystem-backed Store.
type FileStore struct {
	path       string
	currentUID func() uint32
}

var _ Store = (*FileStore)(nil)

// NewFileStore returns a FileStore operating on path.
func NewFileStore(path string) *FileStore {
	return &FileStore{
		path: path,
		currentUID: func() uint32 {
			return uint32(os.Getuid())
		},
	}
}

// Path returns the configured token file path.
func (s *FileStore) Path() string {
	return s.path
}

// Read validates the token file's type, permissions, and owner before returning the trimmed token.
func (s *FileStore) Read() (string, error) {
	linfo, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	if !linfo.Mode().IsRegular() {
		return "", ErrInvalidPermissions
	}

	f, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return "", ErrInvalidPermissions
		}
		return "", err
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return "", err
	}
	if _, err := validateFileInfo(finfo, s.uid()); err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes))
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", ErrEmptyToken
	}
	return tok, nil
}

// Write atomically persists tok with 0600 permissions.
func (s *FileStore) Write(tok string) error {
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.ContainsAny(tok, "\n\r\x00") {
		return errors.New("token must be non-empty and cannot contain CR, LF, or NUL")
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, ".tsudo-token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// Clear removes the token file if it exists.
func (s *FileStore) Clear() error {
	err := os.Remove(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Stat inspects the token file metadata without reading its contents.
func (s *FileStore) Stat() (Info, error) {
	info := Info{Path: s.path}
	fi, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			info.Err = ErrNotFound
			return info, nil
		}
		info.Err = err
		return info, err
	}

	info.Exists = true
	info.Mode = fi.Mode()
	info.ModTime = fi.ModTime()

	uid, err := validateFileInfo(fi, s.uid())
	info.UID = uid
	if err != nil {
		info.Err = err
		return info, nil
	}

	info.Valid = true
	return info, nil
}

func (s *FileStore) uid() uint32 {
	if s.currentUID != nil {
		return s.currentUID()
	}
	return uint32(os.Getuid())
}

func validateFileInfo(fi fs.FileInfo, expectedUID uint32) (uint32, error) {
	var uid uint32
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok {
		uid = st.Uid
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return uid, ErrInvalidPermissions
	}
	if !ok || st.Uid != expectedUID {
		return uid, ErrInvalidOwner
	}
	return uid, nil
}
