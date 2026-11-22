package token

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	t.Run("uses TSUDO_MCP_TOKEN_FILE when set", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_TOKEN_FILE", "/custom/runtime/my-token")
		t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		if got != "/custom/runtime/my-token" {
			t.Fatalf("DefaultPath() = %q, want %q", got, "/custom/runtime/my-token")
		}
	})

	t.Run("falls back to XDG_RUNTIME_DIR/tsudo-token", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_TOKEN_FILE", "")
		t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		want := filepath.Join("/run/user/1000", "tsudo-token")
		if got != want {
			t.Fatalf("DefaultPath() = %q, want %q", got, want)
		}
	})

	t.Run("errors when XDG_RUNTIME_DIR is missing", func(t *testing.T) {
		t.Setenv("TSUDO_MCP_TOKEN_FILE", "")
		t.Setenv("XDG_RUNTIME_DIR", "")

		got, err := DefaultPath()
		if err == nil {
			t.Fatalf("DefaultPath() = %q, expected error when XDG_RUNTIME_DIR is empty", got)
		}
		if strings.Contains(got, "/tmp") {
			t.Fatalf("DefaultPath() must never fall back to /tmp, got %q", got)
		}
	})
}

func TestFileStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "tsudo-token")
	store := NewFileStore(path)

	if store.Path() != path {
		t.Fatalf("Path() = %q, want %q", store.Path(), path)
	}

	// Missing initially.
	if _, err := store.Read(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read() on missing file = %v, want ErrNotFound", err)
	}

	info, err := store.Stat()
	if err != nil {
		t.Fatalf("Stat() on missing file unexpected error: %v", err)
	}
	if info.Exists || info.Valid || !errors.Is(info.Err, ErrNotFound) {
		t.Fatalf("Stat() on missing file = %+v, want Exists=false Valid=false Err=ErrNotFound", info)
	}

	// Write and read.
	if err := store.Write("  tok_secret_12345  "); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	got, err := store.Read()
	if err != nil {
		t.Fatalf("Read() unexpected error: %v", err)
	}
	if got != "tok_secret_12345" {
		t.Fatalf("Read() = %q, want %q", got, "tok_secret_12345")
	}

	info, err = store.Stat()
	if err != nil {
		t.Fatalf("Stat() unexpected error: %v", err)
	}
	if !info.Exists || !info.Valid || info.Err != nil {
		t.Fatalf("Stat() = %+v, want Exists=true Valid=true Err=nil", info)
	}
	if info.Mode.Perm() != 0o600 {
		t.Fatalf("Stat().Mode.Perm() = %o, want 0600", info.Mode.Perm())
	}
	if info.UID != uint32(os.Getuid()) {
		t.Fatalf("Stat().UID = %d, want %d", info.UID, os.Getuid())
	}
	if info.ModTime.IsZero() {
		t.Fatalf("Stat().ModTime is zero")
	}

	// Atomic overwrite.
	if err := store.Write("tok_updated_67890"); err != nil {
		t.Fatalf("Write() overwrite unexpected error: %v", err)
	}
	got, err = store.Read()
	if err != nil {
		t.Fatalf("Read() after overwrite unexpected error: %v", err)
	}
	if got != "tok_updated_67890" {
		t.Fatalf("Read() after overwrite = %q, want %q", got, "tok_updated_67890")
	}

	// Ensure no stray temp files remain in directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "tsudo-token" {
		t.Fatalf("unexpected directory entries after Write: %+v", entries)
	}

	// Clear and idempotent second Clear.
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear() unexpected error: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear() on missing file unexpected error: %v", err)
	}
	if _, err := store.Read(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read() after Clear() = %v, want ErrNotFound", err)
	}
}

func TestFileStoreSecurityRejections(t *testing.T) {
	t.Run("rejects loose permissions", func(t *testing.T) {
		modes := []fs.FileMode{0o644, 0o640, 0o604}
		for _, mode := range modes {
			dir := t.TempDir()
			path := filepath.Join(dir, "tsudo-token")
			if err := os.WriteFile(path, []byte("tok_secret_12345\n"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("Chmod(%o): %v", mode, err)
			}

			store := NewFileStore(path)
			if _, err := store.Read(); !errors.Is(err, ErrInvalidPermissions) {
				t.Fatalf("Read() with mode %o = %v, want ErrInvalidPermissions", mode, err)
			}
			info, err := store.Stat()
			if err != nil {
				t.Fatalf("Stat() with mode %o unexpected error: %v", mode, err)
			}
			if !info.Exists || info.Valid || !errors.Is(info.Err, ErrInvalidPermissions) {
				t.Fatalf("Stat() with mode %o = %+v, want Exists=true Valid=false Err=ErrInvalidPermissions", mode, info)
			}
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-token")
		link := filepath.Join(dir, "tsudo-token")
		if err := os.WriteFile(target, []byte("tok_secret_12345\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		store := NewFileStore(link)
		if _, err := store.Read(); !errors.Is(err, ErrInvalidPermissions) {
			t.Fatalf("Read() on symlink = %v, want ErrInvalidPermissions", err)
		}
		info, err := store.Stat()
		if err != nil {
			t.Fatalf("Stat() on symlink unexpected error: %v", err)
		}
		if !info.Exists || info.Valid || !errors.Is(info.Err, ErrInvalidPermissions) {
			t.Fatalf("Stat() on symlink = %+v, want Exists=true Valid=false Err=ErrInvalidPermissions", info)
		}
	})

	t.Run("rejects empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tsudo-token")
		if err := os.WriteFile(path, []byte("   \n\t "), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		store := NewFileStore(path)
		if _, err := store.Read(); !errors.Is(err, ErrEmptyToken) {
			t.Fatalf("Read() on empty file = %v, want ErrEmptyToken", err)
		}
	})

	t.Run("rejects wrong UID", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tsudo-token")
		if err := os.WriteFile(path, []byte("tok_secret_12345\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		store := NewFileStore(path)
		store.currentUID = func() uint32 { return uint32(os.Getuid()) + 1 }

		if _, err := store.Read(); !errors.Is(err, ErrInvalidOwner) {
			t.Fatalf("Read() with wrong UID = %v, want ErrInvalidOwner", err)
		}
		info, err := store.Stat()
		if err != nil {
			t.Fatalf("Stat() with wrong UID unexpected error: %v", err)
		}
		if !info.Exists || info.Valid || !errors.Is(info.Err, ErrInvalidOwner) {
			t.Fatalf("Stat() with wrong UID = %+v, want Exists=true Valid=false Err=ErrInvalidOwner", info)
		}
	})
}

func TestFileStoreWriteValidation(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "whitespace only", token: "   \t\n "},
		{name: "embedded newline", token: "tok_abc\ntok_def"},
		{name: "embedded carriage return", token: "tok_abc\rtok_def"},
		{name: "embedded nul", token: "tok_abc\x00def"},
		{name: "trailing nul", token: "tok_abc12345\x00"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tsudo-token")
			store := NewFileStore(path)

			if err := store.Write(tc.token); err == nil {
				t.Fatalf("Write(%q) expected error, got nil", tc.token)
			}
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("failed Write(%q) left file behind at %s", tc.token, path)
			}
		})
	}
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr error
	}{
		{
			name: "multi-line tsudo output",
			output: "Authentication succeeded\n" +
				"Temporary tsudo token:\n" +
				"tsudo_tok_9876543210\n" +
				"Expires at: 2026-11-22T20:00:00Z\n",
			want: "tsudo_tok_9876543210",
		},
		{
			name:   "same-line format",
			output: "Temporary tsudo token: tsudo_tok_9876543210\nExpires at: soon\n",
			want:   "tsudo_tok_9876543210",
		},
		{
			name:   "CRLF line endings",
			output: "Temporary tsudo token:\r\ntsudo_tok_crlf_1234\r\nExpires at: later\r\n",
			want:   "tsudo_tok_crlf_1234",
		},
		{
			name:    "missing header",
			output:  "some random output\nwithout a token\n",
			wantErr: ErrTokenNotFoundInOutput,
		},
		{
			name:    "empty token after header",
			output:  "Temporary tsudo token:\n\n",
			wantErr: ErrTokenNotFoundInOutput,
		},
		{
			name:    "short token",
			output:  "Temporary tsudo token:\nabc123\n",
			wantErr: ErrTokenNotFoundInOutput,
		},
		{
			name:    "token with whitespace",
			output:  "Temporary tsudo token:\ntoken with spaces\n",
			wantErr: ErrTokenNotFoundInOutput,
		},
		{
			name:    "same-line token with whitespace",
			output:  "Temporary tsudo token: tok12345 extra\n",
			wantErr: ErrTokenNotFoundInOutput,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseToken(tc.output)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseToken() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseToken() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ParseToken() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		tok  string
		want string
	}{
		{
			name: "empty token leaves input unchanged",
			in:   "hello world",
			tok:  "",
			want: "hello world",
		},
		{
			name: "replaces all occurrences of token",
			in:   "cmd failed with tok_secret_123 and tok_secret_123",
			tok:  "tok_secret_123",
			want: "cmd failed with [REDACTED] and [REDACTED]",
		},
		{
			name: "input without token unchanged",
			in:   "clean output",
			tok:  "tok_secret_123",
			want: "clean output",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.in, tc.tok); got != tc.want {
				t.Fatalf("Redact() = %q, want %q", got, tc.want)
			}
		})
	}
}
