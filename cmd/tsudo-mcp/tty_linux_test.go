//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

const (
	tiocsptlck = 0x40045431
	tiocgptn   = 0x80045430
)

func openTestPTY(t *testing.T) (ptmx *os.File, pts *os.File) {
	t.Helper()

	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENXIO) {
			t.Skipf("skipping PTY test: /dev/ptmx unavailable: %v", err)
		}
		t.Fatalf("open /dev/ptmx: %v", err)
	}

	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), tiocsptlck, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		_ = ptmx.Close()
		t.Fatalf("ioctl TIOCSPTLCK: %v", errno)
	}

	var ptn uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), tiocgptn, uintptr(unsafe.Pointer(&ptn))); errno != 0 {
		_ = ptmx.Close()
		t.Fatalf("ioctl TIOCGPTN: %v", errno)
	}

	ptsPath := fmt.Sprintf("/dev/pts/%d", ptn)
	pts, err = os.OpenFile(ptsPath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Fatalf("open %s: %v", ptsPath, err)
	}

	t.Cleanup(func() {
		_ = pts.Close()
		_ = ptmx.Close()
	})

	return ptmx, pts
}

func getTermios(t *testing.T, f *os.File) syscall.Termios {
	t.Helper()

	var termios syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios))); errno != 0 {
		t.Fatalf("ioctl TCGETS: %v", errno)
	}
	return termios
}

func setTermios(t *testing.T, f *os.File, termios syscall.Termios) {
	t.Helper()

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&termios))); errno != 0 {
		t.Fatalf("ioctl TCSETS: %v", errno)
	}
}

func TestDisableEchoIfTTYIdempotentCleanup(t *testing.T) {
	_, pts := openTestPTY(t)

	orig := getTermios(t, pts)
	orig.Lflag |= syscall.ECHO | syscall.ICANON | syscall.ISIG
	setTermios(t, pts, orig)

	cleanup := disableEchoIfTTY(pts)

	whileDisabled := getTermios(t, pts)
	if whileDisabled.Lflag&syscall.ECHO != 0 {
		t.Fatalf("expected ECHO to be cleared, Lflag=%#x", whileDisabled.Lflag)
	}
	if whileDisabled.Lflag&syscall.ICANON == 0 {
		t.Fatalf("expected ICANON to remain set, Lflag=%#x", whileDisabled.Lflag)
	}
	if whileDisabled.Lflag&syscall.ISIG == 0 {
		t.Fatalf("expected ISIG to remain set, Lflag=%#x", whileDisabled.Lflag)
	}

	cleanup()

	restored := getTermios(t, pts)
	if restored.Lflag&syscall.ECHO == 0 {
		t.Fatalf("expected ECHO to be restored after cleanup, Lflag=%#x", restored.Lflag)
	}

	// Sequential second call must be a safe no-op.
	cleanup()

	// Concurrent calls must be race-free and panic-free.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanup()
		}()
	}
	wg.Wait()

	afterConcurrent := getTermios(t, pts)
	if afterConcurrent.Lflag&syscall.ECHO == 0 {
		t.Fatalf("expected ECHO to remain restored, Lflag=%#x", afterConcurrent.Lflag)
	}
}

func TestGrantWithTTYStdinDoesNotPanic(t *testing.T) {
	const secretToken = "tok_tty_secret_123456"

	_, pts := openTestPTY(t)
	orig := getTermios(t, pts)
	orig.Lflag |= syscall.ECHO | syscall.ICANON | syscall.ISIG
	setTermios(t, pts, orig)

	tokPath := filepath.Join(t.TempDir(), "tsudo-token")
	t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

	script := "printf 'sudo password: '\n" +
		"printf '\\nTemporary tsudo token:\\n" + secretToken + "\\nExpires at: 2026-11-22T20:00:00Z\\n'\n"
	fakeTsudo := writeFakeTsudoScript(t, script)

	var stdout, stderr bytes.Buffer
	code := runWithBinary([]string{"grant", "10m"}, fakeTsudo, pts, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	if strings.Contains(stdout.String(), secretToken) || strings.Contains(stderr.String(), secretToken) {
		t.Fatalf("raw token leaked in output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	info, err := os.Stat(tokPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %04o, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(tokPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if strings.TrimSpace(string(data)) != secretToken {
		t.Fatalf("token file content = %q, want %q", strings.TrimSpace(string(data)), secretToken)
	}

	after := getTermios(t, pts)
	if after.Lflag&syscall.ECHO == 0 {
		t.Fatalf("expected ECHO to be restored after runGrant, Lflag=%#x", after.Lflag)
	}
}
