package mirror

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func yamlNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newMirror(t *testing.T, upstream string) *Mirror {
	t.Helper()
	tr, err := factory(yamlNode(t, "upstream: \""+upstream+"\"\nrules:\n  - host: \"update.code.visualstudio.com\"\n"), slog.Default())
	require.NoError(t, err)
	return tr.(*Mirror)
}

func mitmReq(method, rawurl string) (*transform.TransformContext, *http.Request) {
	return &transform.TransformContext{Mode: transform.ModeMITM, Logger: slog.Default()},
		httptest.NewRequest(method, rawurl, nil)
}

func TestMirror_ServesMatchingFromUpstream(t *testing.T) {
	const body = "PRETEND-CLI-ALPINE-TARBALL-BYTES"
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/octet-stream")
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:abcabc/cli-alpine-x64/stable")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.NotNil(t, res.Response)
	require.Equal(t, http.StatusOK, res.Response.StatusCode)
	require.Equal(t, "application/octet-stream", res.Response.Header.Get("Content-Type"))

	got, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.NoError(t, res.Response.Body.Close())
	require.Equal(t, body, string(got))
	// Path-transparent: the mirror is hit with the exact origin path.
	require.Equal(t, "/commit:abcabc/cli-alpine-x64/stable", gotPath)
}

func TestMirror_StreamsLargeBody(t *testing.T) {
	big := strings.Repeat("x", 5<<20) // 5 MiB, well past any buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:x/server-linux-arm64/stable")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	got, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.NoError(t, res.Response.Body.Close())
	require.Len(t, got, len(big))
}

func TestMirror_NonMatchingHostContinues(t *testing.T) {
	m := newMirror(t, "http://127.0.0.1:1") // must not be dialed
	tctx, req := mitmReq("GET", "https://example.com/whatever")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, res.Response)
}

func TestMirror_ConnectNotMirrored(t *testing.T) {
	// The CONNECT that establishes the MITM tunnel matches the host but must NOT
	// be stubbed (that returns 404 for the CONNECT and kills the tunnel).
	m := newMirror(t, "http://127.0.0.1:1") // must not be dialed
	tctx := &transform.TransformContext{Mode: transform.ModeMITM, Logger: slog.Default()}
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "update.code.visualstudio.com:443",
		URL:    &url.URL{Host: "update.code.visualstudio.com:443"},
	}
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, res.Response)
}

func TestMirror_SNIOnlyContinues(t *testing.T) {
	m := newMirror(t, "http://127.0.0.1:1")
	_, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:x/cli-alpine-x64/stable")
	tctx := &transform.TransformContext{Mode: transform.ModeSNIOnly, Logger: slog.Default()}
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestMirror_UnreachableIsStub502(t *testing.T) {
	m := newMirror(t, "http://127.0.0.1:1") // nothing listening
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:x/cli-alpine-x64/stable")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
}

func TestMirror_UpstreamStatusPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // e.g. Microsoft GC'd this commit
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, "gone")
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:deadbeef/cli-alpine-x64/stable")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, http.StatusNotFound, res.Response.StatusCode)
}

func TestMirror_FactoryValidation(t *testing.T) {
	_, err := factory(yamlNode(t, "rules:\n  - host: \"x\"\n"), slog.Default())
	require.ErrorContains(t, err, "upstream")
	_, err = factory(yamlNode(t, "upstream: \"http://x\"\n"), slog.Default())
	require.ErrorContains(t, err, "rules")
}

// TestMirror_RelaysClientRequestHeaders is the ENG-1953 regression: the client's
// headers must reach the mirror intact (Authorization above all — dropping it is
// what made every Copilot call arrive anonymous), while hop-by-hop,
// connection-scoped, proxy-scoped and body-framing headers must not travel.
func TestMirror_RelaysClientRequestHeaders(t *testing.T) {
	var got http.Header
	var gotHost, gotMethod string
	var gotBody []byte
	var gotContentLength int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotHost, gotMethod, gotContentLength = r.Host, r.Method, r.ContentLength
		gotBody, _ = io.ReadAll(r.Body)
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/copilot_internal/v2/token")
	req.Header.Set("Authorization", "Bearer gho_pretend-token")
	req.Header.Set("Editor-Version", "vscode/1.99.0")
	req.Header.Set("User-Agent", "GitHubCopilotChat/0.26.0")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept", "text/plain")
	// Hop-by-hop and connection-scoped: must be stripped.
	req.Header.Set("Connection", "keep-alive, X-Hop-Token")
	req.Header.Set("X-Hop-Token", "named-by-connection")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Trailer", "X-Checksum")
	// Proxy-scoped: addressed to a proxy, never relayed onward.
	req.Header.Set("Proxy-Authorization", "Basic c2hvdWxkOm5vdC1sZWFr")
	req.Header.Set("Proxy-Connection", "keep-alive")
	// Body framing: the mirror fetch is a bodyless GET by contract.
	req.Header.Set("Content-Length", "1234")
	req.Header.Set("Expect", "100-continue")
	// The origin's Host must not be imposed on the mirror.
	req.Header.Set("Host", "update.code.visualstudio.com")

	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.NoError(t, res.Response.Body.Close())

	// Relayed intact, including a repeated header's full value list.
	require.Equal(t, "Bearer gho_pretend-token", got.Get("Authorization"))
	require.Equal(t, "vscode/1.99.0", got.Get("Editor-Version"))
	require.Equal(t, "GitHubCopilotChat/0.26.0", got.Get("User-Agent"))
	require.Equal(t, []string{"application/json", "text/plain"}, got.Values("Accept"))

	for _, k := range []string{
		"Connection", "X-Hop-Token", "Keep-Alive", "Transfer-Encoding", "Upgrade",
		"TE", "Trailer", "Proxy-Authorization", "Proxy-Connection", "Expect",
	} {
		require.Empty(t, got.Values(k), "hop-by-hop header %q must not reach the mirror", k)
	}

	// Host comes from the mirror target, not from the client's request.
	require.Equal(t, srv.Listener.Addr().String(), gotHost)
	require.NotContains(t, gotHost, "visualstudio.com")

	// GET, and no request body ever reaches an origin through the mirror.
	require.Equal(t, http.MethodGet, gotMethod)
	require.Empty(t, gotBody)
	require.Zero(t, gotContentLength)
}

// TestMirror_PassesBackActionableResponseHeaders is the response half of
// ENG-1953: GitHub explains a 401 or a 429, and the client has to see the
// explanation to act on it.
func TestMirror_PassesBackActionableResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("WWW-Authenticate", `Bearer realm="github", error="invalid_token"`)
		h.Set("Retry-After", "60")
		h.Set("X-RateLimit-Limit", "60")
		h.Set("X-RateLimit-Remaining", "0")
		h.Set("X-RateLimit-Reset", "1756400000")
		h.Set("X-RateLimit-Resource", "core")
		h.Set("Cache-Control", "no-store, private")
		h.Set("Vary", "Accept-Encoding, Authorization")
		h.Set("Accept-Ranges", "bytes")
		h.Set("Content-Type", "application/json")
		h.Set("ETag", `W/"abc123"`)
		// Not on the allowlist: the response direction stays a closed set.
		h.Set("Set-Cookie", "session=leak; Path=/")
		h.Set("X-Github-Request-Id", "DEAD:BEEF")
		w.WriteHeader(http.StatusUnauthorized)
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/copilot_internal/user")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, http.StatusUnauthorized, res.Response.StatusCode)

	h := res.Response.Header
	require.Equal(t, `Bearer realm="github", error="invalid_token"`, h.Get("WWW-Authenticate"))
	require.Equal(t, "60", h.Get("Retry-After"))
	require.Equal(t, "60", h.Get("X-RateLimit-Limit"))
	require.Equal(t, "0", h.Get("X-RateLimit-Remaining"))
	require.Equal(t, "1756400000", h.Get("X-RateLimit-Reset"))
	require.Equal(t, "core", h.Get("X-RateLimit-Resource"))
	require.Equal(t, "no-store, private", h.Get("Cache-Control"))
	require.Equal(t, "Accept-Encoding, Authorization", h.Get("Vary"))
	require.Equal(t, "bytes", h.Get("Accept-Ranges"))
	require.Equal(t, "application/json", h.Get("Content-Type"))
	require.Equal(t, `W/"abc123"`, h.Get("ETag"))

	// Still an allowlist, not a blanket copy.
	require.Empty(t, h.Values("Set-Cookie"))
	require.Empty(t, h.Values("X-Github-Request-Id"))

	body, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.NoError(t, res.Response.Body.Close())
	require.Equal(t, `{"message":"Bad credentials"}`, string(body))
}

// TestMirror_RangeRequestRoundTrips is why Accept-Ranges/Content-Range joined the
// allowlist: relaying the client's Range header makes 206 newly reachable, and a
// 206 stripped of Content-Range is undecodable.
func TestMirror_RangeRequestRoundTrips(t *testing.T) {
	var gotRange string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		w.Header().Set("Content-Range", "bytes 0-3/32")
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)
		// Test-server handler: a write failure here surfaces as a client-side
		// assertion failure below, so the error is deliberately ignored.
		_, _ = io.WriteString(w, "PRET")
	}))
	defer srv.Close()

	m := newMirror(t, srv.URL)
	tctx, req := mitmReq("GET", "https://update.code.visualstudio.com/commit:x/server-linux-arm64/stable")
	req.Header.Set("Range", "bytes=0-3")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.NoError(t, res.Response.Body.Close())
	require.Equal(t, "bytes=0-3", gotRange)
	require.Equal(t, http.StatusPartialContent, res.Response.StatusCode)
	require.Equal(t, "bytes 0-3/32", res.Response.Header.Get("Content-Range"))
	require.Equal(t, "bytes", res.Response.Header.Get("Accept-Ranges"))
}

// TestMirror_RelayDoesNotWidenRouting pins the security property: relaying
// headers changes only what travels on an ALREADY-PERMITTED request. A host the
// route table does not list is still not fetched, credentials and all.
func TestMirror_RelayDoesNotWidenRouting(t *testing.T) {
	m := newMirror(t, "http://127.0.0.1:1") // must not be dialed
	tctx, req := mitmReq("GET", "https://api.github.com/user")
	req.Header.Set("Authorization", "Bearer gho_pretend-token")
	res, err := m.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, res.Response)
}
