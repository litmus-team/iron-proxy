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
		io.WriteString(w, body)
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
		io.WriteString(w, big)
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
		io.WriteString(w, "gone")
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
