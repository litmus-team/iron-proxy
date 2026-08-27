package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// rawRequest writes a request byte-for-byte over TCP so dot segments reach the
// proxy unnormalized. net/http's client collapses "/a/../b" to "/b" before the
// request ever leaves the process, which would defeat the point of this test.
func rawRequest(t *testing.T, proxyAddr, raw string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(raw))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return string(buf[:n])
}

// TestHTTPProxy_BodyCapture_DotSegmentPathCannotEvadeCapture is the regression
// test for the hole this fork rebased onto v0.49.0 to close (ENG-1442).
//
// On v0.31 a request path containing ".." was forwarded to the upstream
// verbatim. body_capture matches its rules against that raw path, so
// "/v1/messages/../../v1/messages" did NOT match a rule scoped to
// "/v1/messages" — while an upstream that canonicalizes the path served the
// request anyway. The capture lane went dark: the prompt was answered and
// nothing was recorded, which reads downstream as a candidate who used no AI
// at all.
//
// The guard upstream added in v0.36.0 (handleHTTP -> containsDotSegments)
// rejects the request with 400 before the transform pipeline runs, so the
// evasion is no longer reachable. This test pins that at the proxy level with
// the real body_capture transform in the pipeline, because
// TestHTTPProxy_RejectsDotSegmentPaths upstream proves only the generic
// rejection and never exercises the capture path.
func TestHTTPProxy_BodyCapture_DotSegmentPathCannotEvadeCapture(t *testing.T) {
	upstreamHit := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case upstreamHit <- struct{}{}:
		default:
		}
		_, _ = io.WriteString(w, `{"content":"secret model reply"}`)
	}))
	defer upstream.Close()

	// Scoped exactly the way a capture deployment scopes it: one host, one path.
	bc := newBodyCaptureTransform(t, `
rules:
  - host: "127.0.0.1"
    methods: [POST]
    paths: ["/v1/messages"]
`)
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	// A path carrying ".." that does not literally match the capture rule but
	// canonicalizes straight back to the path it protects.
	body := `{"messages":[{"role":"user","content":"evade me"}]}`
	raw := fmt.Sprintf("POST /v1/messages/../../v1/messages HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s",
		upstream.Listener.Addr().String(), len(body), body)

	resp := rawRequest(t, proxyAddr, raw)

	require.Contains(t, resp, "400",
		"a request path containing .. must be rejected, not forwarded")
	require.NotContains(t, resp, "secret model reply")

	select {
	case <-upstreamHit:
		t.Fatal("upstream was reached by a dot-segment path — the guard is gone")
	case <-time.After(250 * time.Millisecond):
	}

	// Nothing reached the capture lane either: the request was rejected ahead
	// of the pipeline, so there is no half-captured record to reason about.
	select {
	case result := <-results:
		require.Nil(t, result.BodyCapture,
			"a rejected dot-segment request must not produce a capture record")
	case <-time.After(250 * time.Millisecond):
		// No audit record at all — rejected before the pipeline ran.
	}
}

// TestHTTPProxy_BodyCapture_CanonicalPathIsCaptured is the positive control for
// the test above. It proves the rule used there is live and would have captured
// that request, so the 400 is attributable to the dot-segment guard rather than
// to a rule that never matched anything.
func TestHTTPProxy_BodyCapture_CanonicalPathIsCaptured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":"model reply"}`)
	}))
	defer upstream.Close()

	bc := newBodyCaptureTransform(t, `
rules:
  - host: "127.0.0.1"
    methods: [POST]
    paths: ["/v1/messages"]
`)
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	body := `{"messages":[{"role":"user","content":"hello"}]}`
	req, err := http.NewRequest("POST", "http://"+proxyAddr+"/v1/messages",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"content":"model reply"}`, string(got))

	result := awaitAudit(t, results)
	require.NotNil(t, result.BodyCapture, "the canonical path must be captured")
	require.Equal(t, body, result.BodyCapture.RequestBody())
	require.False(t, result.BodyCapture.RequestBodyTruncated())
}
