package runner

import (
	"bytes"
	"sync"
)

// LimitedBuffer is a thread-safe io.Writer that stores up to a fixed byte limit
// and silently discards excess bytes while marking the buffer as truncated.
type LimitedBuffer struct {
	mu        sync.Mutex
	limit     int
	buf       bytes.Buffer
	truncated bool
}

// NewLimitedBuffer returns a LimitedBuffer capped at limit bytes.
func NewLimitedBuffer(limit int) *LimitedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &LimitedBuffer{limit: limit}
}

// Write appends up to the remaining capacity from p into the buffer and
// discards any excess bytes, always returning len(p), nil.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	rem := b.limit - b.buf.Len()
	if rem <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > rem {
		_, _ = b.buf.Write(p[:rem])
		b.truncated = true
		return len(p), nil
	}

	_, _ = b.buf.Write(p)
	return len(p), nil
}

// Truncated reports whether any written bytes were discarded due to the limit.
func (b *LimitedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// String returns the captured contents of the buffer.
func (b *LimitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
