// Package mirror implements a transform that serves matching requests from a
// caching mirror instead of the real origin, terminating them at the proxy with
// a synthetic (ActionStub) response.
//
// Its motivating use is VS Code Remote-SSH under sealed egress (Litmus
// Codespaces v2): the candidate container's egress is default-denied, so
// Remote-SSH's in-container download of vscode-server from
// update.code.visualstudio.com fails (even the in-container proxy's own upstream
// to Microsoft is denied). This transform intercepts requests to the configured
// hosts — already MITM'd by the proxy — and serves the response from a mirror
// the proxy CAN reach (a Litmus-controlled host that caches the artifacts
// out-of-band). The client never learns it isn't talking to the origin, and the
// sealed-egress posture is unchanged: the proxy stays the sole egress mediator,
// it reaches only the mirror, and only the mirror reaches the origin.
//
// Transparent by design — it covers every artifact the bootstrap fetches (the
// cli-alpine-x64 launcher AND the server) and every tool that hits the origin
// through the proxy (VS Code, Cursor), with no client configuration. Requires
// MITM mode (it terminates TLS to serve the synthetic response); in sni-only
// mode there is no path to mirror, so it no-ops.
package mirror

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("mirror", factory)
}

type config struct {
	// Upstream is the base URL of the mirror (e.g. "http://10.0.0.5:8079"). The
	// request path (+ raw query) is appended verbatim, so the mirror must be
	// path-transparent with the origin it stands in for.
	Upstream string `yaml:"upstream"`
	// Rules select which requests are served from the mirror (host/method/path).
	Rules []hostmatch.RuleConfig `yaml:"rules"`
	// ResponseHeaderTimeoutSeconds bounds the wait for the mirror's response
	// headers — NOT the body, so large tarballs still stream. Default 30s.
	ResponseHeaderTimeoutSeconds int `yaml:"response_header_timeout_seconds,omitempty"`
}

// Mirror serves matching requests from a caching mirror.
type Mirror struct {
	upstream string
	rules    []hostmatch.Rule
	client   *http.Client
	logger   *slog.Logger
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing mirror config: %w", err)
	}
	if c.Upstream == "" {
		return nil, fmt.Errorf("mirror: \"upstream\" is required")
	}
	if len(c.Rules) == 0 {
		return nil, fmt.Errorf("mirror: at least one entry in \"rules\" is required")
	}
	rules, err := hostmatch.CompileRules(c.Rules, "mirror")
	if err != nil {
		return nil, err
	}
	hdrTimeout := 30 * time.Second
	if c.ResponseHeaderTimeoutSeconds > 0 {
		hdrTimeout = time.Duration(c.ResponseHeaderTimeoutSeconds) * time.Second
	}
	return &Mirror{
		upstream: strings.TrimRight(c.Upstream, "/"),
		rules:    rules,
		// A dedicated client that NEVER honours HTTP(S)_PROXY: the proxy process
		// may itself run with proxy env set, and routing the mirror fetch back
		// through ourselves would loop. No overall client timeout, so large
		// tarballs stream unbounded; dial + response-header timeouts bound setup.
		// DisableCompression keeps the bytes (and Content-Length) verbatim so we
		// pass them through faithfully rather than silently re-decoding.
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				ResponseHeaderTimeout: hdrTimeout,
				DisableCompression:    true,
			},
		},
		logger: logger,
	}, nil
}

// Name implements transform.Transformer.
func (m *Mirror) Name() string { return "mirror" }

// TransformRequest serves a matching request from the mirror.
func (m *Mirror) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Only mirror real download GETs. Crucially, DO NOT act on the CONNECT that
	// establishes the MITM tunnel: it also matches the host rule and runs in
	// ModeMITM, but it has no download path — stubbing it returns a 404 for the
	// CONNECT and kills the tunnel ("CONNECT tunnel failed, response 404"). The
	// transform runs again on the inner GET once the tunnel is up, which is where
	// the actual mirroring happens.
	if req.Method != http.MethodGet || tctx.Mode != transform.ModeMITM || !hostmatch.MatchAnyRule(m.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	target := m.upstream + req.URL.RequestURI() // path + raw query, verbatim
	tctx.Annotate("mirror_host", hostmatch.StripPort(req.Host))
	tctx.Annotate("mirror_target", target)

	mreq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{Action: transform.ActionStub, Response: synth(req, http.StatusBadGateway, "mirror request build failed")}, nil
	}
	resp, err := m.client.Do(mreq)
	if err != nil {
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{Action: transform.ActionStub, Response: synth(req, http.StatusBadGateway, "mirror unreachable")}, nil
	}
	tctx.Annotate("mirror_status", resp.StatusCode)

	// Stream the mirror's response straight to the client. writeResponse copies
	// Body directly and the copied headers carry Content-Length. The proxy does
	// NOT close a stub Response.Body, and this Body holds a live upstream
	// connection, so wrap it to self-close on EOF (and be idempotent on Close).
	out := &http.Response{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        passthroughHeaders(resp.Header),
		Body:          &eofCloser{rc: resp.Body},
		ContentLength: resp.ContentLength,
		Request:       req,
	}
	return &transform.TransformResult{Action: transform.ActionStub, Response: out}, nil
}

// TransformResponse is a no-op; the mirror acts entirely on the request side.
func (m *Mirror) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// passthroughHeaders copies the headers a downloading client needs to interpret
// the body correctly, dropping hop-by-hop and connection-scoped headers.
func passthroughHeaders(h http.Header) http.Header {
	out := http.Header{}
	for _, k := range []string{"Content-Type", "Content-Length", "Content-Encoding", "ETag", "Last-Modified"} {
		if v := h.Values(k); len(v) > 0 {
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}

func synth(req *http.Request, code int, msg string) *http.Response {
	body := transform.NewBufferedBodyFromBytes([]byte(msg + "\n"))
	return &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:          body,
		ContentLength: int64(len(msg) + 1),
		Request:       req,
	}
}

// eofCloser closes the underlying upstream body once it is fully read (or errors),
// since the proxy's stub-response writer copies the body but never closes it.
// Close is idempotent so a belt-and-suspenders close elsewhere is harmless.
type eofCloser struct {
	rc     io.ReadCloser
	closed bool
}

func (e *eofCloser) Read(p []byte) (int, error) {
	n, err := e.rc.Read(p)
	if err != nil && !e.closed {
		e.closed = true
		_ = e.rc.Close()
	}
	return n, err
}

func (e *eofCloser) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.rc.Close()
}
