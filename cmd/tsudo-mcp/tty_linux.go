//go:build linux

package main

import (
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

// disableEchoIfTTY disables terminal ECHO on r if r is an *os.File backed by a
// TTY, preserving ICANON and ISIG. It returns an idempotent cleanup function
// that restores the original Termios once and stops signal monitoring, making
// it safe to call multiple times (e.g., via both explicit call and defer).
func disableEchoIfTTY(r io.Reader) func() {
	f, ok := r.(*os.File)
	if !ok {
		return func() {}
	}

	fd := f.Fd()
	var orig syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&orig))); errno != 0 {
		return func() {}
	}

	noEcho := orig
	noEcho.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&noEcho))); errno != 0 {
		return func() {}
	}

	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&orig)))
		})
	}

	sigCh := make(chan os.Signal, 1)
	doneCh := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			restore()
		case <-doneCh:
		}
	}()

	var cleanupOnce sync.Once
	return func() {
		cleanupOnce.Do(func() {
			signal.Stop(sigCh)
			close(doneCh)
			restore()
		})
	}
}
