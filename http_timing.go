package blockcheck

import (
	"context"
	"io"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

type responseStart struct {
	started time.Time
	// Offset by one so an observed 0 ms is distinct from no observation.
	elapsed atomic.Int64
}

func (t *responseStart) observe() {
	t.elapsed.CompareAndSwap(0, time.Since(t.started).Milliseconds()+1)
}

func (t *responseStart) milliseconds() *int64 {
	if value := t.elapsed.Load(); value != 0 {
		ms := value - 1
		return &ms
	}
	return nil
}

func (t *responseStart) trace(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: t.observe})
}

type responseStartReader struct {
	io.Reader
	timing *responseStart
}

func (r responseStartReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.timing.observe()
	}
	return n, err
}
