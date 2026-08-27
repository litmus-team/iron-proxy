package mirror

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// TestMirror_ServesFirstByteBeforeUpstreamFinishes is the streaming proof for
// the mirror transform, and the reason this fork exists at all.
//
// TestMirror_StreamsLargeBody only shows that a 5 MiB body arrives intact — an
// implementation that read the whole reply into memory first would pass it just
// as happily. This test cannot be satisfied by buffering: the mirror upstream
// writes ONE byte, flushes, and then refuses to write another until the test
// has already read that byte back out of the transform's response. A mirror
// that buffered the reply before handing it over would deadlock — it would be
// waiting for an upstream body that is itself waiting on the reader — and the
// test fails on its deadline instead of passing quietly.
//
// This matters because the mirror serves a 107 MB Cursor tarball and a 223 MB
// VS Code server. Upstream's generic gRPC alternative buffers a whole streaming
// reply and took a measured 1 ms -> 1006 ms time-to-first-byte on a 1 s stream;
// at these body sizes that is not a latency regression but an out-of-memory.
func TestMirror_ServesFirstByteBeforeUpstreamFinishes(t *testing.T) {
	release := make(chan struct{})
	rest := strings.Repeat("x", 1<<20) // 1 MiB tail, written only after release

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "test server must support flushing")

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "S")
		flusher.Flush()

		// The tail is withheld until the test proves it already has byte 1.
		select {
		case <-release:
		case <-time.After(10 * time.Second):
			t.Error("test never read the first byte — the mirror buffered the reply")
			return
		}
		_, _ = io.WriteString(w, rest)
		flusher.Flush()
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:abc/server-linux-x64/stable")

	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.NotNil(t, res.Response)
	defer res.Response.Body.Close()

	// Read the first byte with a watchdog so a buffering regression fails fast
	// and legibly rather than hanging until the package test timeout.
	type readResult struct {
		b   []byte
		err error
	}
	first := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 1)
		n, err := io.ReadFull(res.Response.Body, buf)
		first <- readResult{b: buf[:n], err: err}
	}()

	start := time.Now()
	select {
	case got := <-first:
		require.NoError(t, got.err)
		require.Equal(t, "S", string(got.b))
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("first byte never arrived: the mirror buffered the response " +
			"instead of streaming it")
	}
	ttfb := time.Since(start)
	t.Logf("time-to-first-byte after transform returned: %s", ttfb)

	// The upstream had written exactly one byte at this point, so receiving it
	// proves the body was forwarded live rather than after completion.
	close(release)

	tail, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.Len(t, tail, len(rest), "the rest of the body must still arrive intact")
}

// TestMirror_TransformReturnsBeforeBodyIsRead pins the other half of the
// streaming contract: TransformRequest must return as soon as the mirror's
// response HEADERS are in, without touching the body. If it ever starts
// draining the body itself, a 223 MB download would stall the whole request
// pipeline — and every other transform behind it — for the length of the
// transfer.
func TestMirror_TransformReturnsBeforeBodyIsRead(t *testing.T) {
	bodyStarted := make(chan struct{})
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush() // headers out, body withheld
		close(bodyStarted)
		<-release
	}))
	// Release the handler BEFORE closing the server: httptest.Server.Close
	// waits for outstanding handlers to return, so closing first would deadlock
	// against a handler that is still parked on <-release.
	defer func() {
		close(release)
		srv.Close()
	}()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:abc/cli-linux-x64/stable")

	done := make(chan struct{})
	go func() {
		defer close(done)
		res, err := m.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionStub, res.Action)
		_ = res.Response.Body.Close()
	}()

	<-bodyStarted
	select {
	case <-done:
		// TransformRequest returned while the upstream body was still open.
	case <-time.After(3 * time.Second):
		t.Fatal("TransformRequest blocked on the response body instead of " +
			"returning once headers arrived")
	}
}
