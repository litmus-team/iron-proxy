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
	// Relay the client's own headers onto the mirror fetch. Omitting this is
	// ENG-1953: the mirror saw a bare "User-Agent: Go-http-client/1.1" and every
	// client header — Authorization above all — vanished by omission, with no
	// filter to log and nothing to grep. Copilot's token calls therefore reached
	// GitHub anonymous, drew the mirror VM's shared-IP rate limit, and Copilot
	// unregistered its BYOK providers. Still a bodyless GET: nothing here adds a
	// body, and the body-framing headers are dropped (see relayRequestHeaders).
	mreq.Header = relayRequestHeaders(req.Header)
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

// hopByHopRequestHeaders never travel to the mirror. Keys are in the canonical
// form http.Header uses, hence "Te" rather than "TE" — CanonicalHeaderKey
// title-cases each dash-separated token, so a literal "TE" would never match.
//
// The first group is hop-by-hop / connection-scoped (RFC 9110 section 7.6.1):
// these describe THIS connection rather than the message, so forwarding them
// corrupts the next hop's framing. Host is second: NewRequestWithContext already
// derives it from the mirror target, and relaying the origin's Host would send
// the mirror a request addressed to somebody else. (Go's server promotes Host
// out of Header into Request.Host, so that one is belt-and-suspenders.) The last
// group is body framing: the mirror fetch is a bodyless GET by contract, and
// Content-Length or Expect would describe a body that is never sent — Expect:
// 100-continue in particular leaves the origin waiting for one that never comes.
var hopByHopRequestHeaders = map[string]bool{
	"Connection":        true,
	"Keep-Alive":        true,
	"Transfer-Encoding": true,
	"Upgrade":           true,
	"Te":                true,
	"Trailer":           true,

	"Host": true,

	"Content-Length": true,
	"Expect":         true,
}

// relayRequestHeaders builds the header set the mirror fetch carries, copying
// the client's headers minus the ones that must not cross a hop.
//
// Copy-minus-hop-by-hop, deliberately NOT an allowlist. An allowlist looks
// safer, but it fails in precisely the way ENG-1953 failed: the next header the
// client starts sending is dropped silently, nothing logs it, and the symptom
// surfaces somewhere far away as an unexplained 401 or rate-limit. A denylist
// fails loudly instead — anything that must not travel is written down right
// here, in one list a reviewer can read. What bounds the blast radius is not
// this function but the route table: only requests already matched by m.rules
// are mirrored at all, so a relayed credential reaches only the operator's
// configured upstream, and only for the host/path pairs the operator listed.
//
// Proxy-* is dropped by prefix: those headers are addressed to a proxy, not to
// an origin, and Proxy-Authorization in particular must not leak onward.
func relayRequestHeaders(h http.Header) http.Header {
	// RFC 9110 section 7.6.1: Connection's value names FURTHER headers that are
	// scoped to this connection alone. Honouring that is what makes the denylist
	// complete rather than merely long — the client can name headers we could
	// not have enumerated ahead of time.
	var connScoped map[string]bool
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if connScoped == nil {
				connScoped = map[string]bool{}
			}
			connScoped[http.CanonicalHeaderKey(tok)] = true
		}
	}

	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		if hopByHopRequestHeaders[ck] || connScoped[ck] || strings.HasPrefix(strings.ToLower(ck), "proxy-") {
			continue
		}
		out[ck] = append([]string(nil), vs...)
	}
	return out
}

// passthroughHeaderNames are the response headers copied back to the client.
//
// This direction stays an allowlist, unlike the request direction above. The
// asymmetry is deliberate: a request must carry whatever the client invents
// next, whereas a response header we did not plan for is a liability around a
// synthetic stub (a Connection directive we cannot honour, a Set-Cookie the
// mirror had no business minting) rather than something lost. Three groups:
//
//   - Body shape, so the bytes decode: Content-Type/Length/Encoding, plus
//     Accept-Ranges and Content-Range. Those two are newly load-bearing now that
//     the client's Range header is relayed upstream — a 206 whose Content-Range
//     we stripped would be undecodable.
//   - Validators and caching: ETag, Last-Modified, Cache-Control, Vary.
//   - Failure semantics, so a client can ACT on a failure instead of guessing at
//     it: WWW-Authenticate says why a 401 happened, Retry-After and X-RateLimit-*
//     say when a 429 clears. Dropping these is the other half of ENG-1953 —
//     GitHub explained the rate limit and the client never saw the explanation.
var passthroughHeaderNames = []string{
	"Content-Type", "Content-Length", "Content-Encoding",
	"Accept-Ranges", "Content-Range",
	"ETag", "Last-Modified", "Cache-Control", "Vary",
	"WWW-Authenticate", "Retry-After",
}

// passthroughHeaderPrefixes matches header families whose members cannot be
// enumerated ahead of time. Lowercase, and matched against a lowercased key:
// canonicalization renders X-RateLimit-Remaining as X-Ratelimit-Remaining, so a
// case-sensitive prefix would silently miss every single one of them.
var passthroughHeaderPrefixes = []string{"x-ratelimit-"}

// passthroughHeaders copies the headers a client needs to interpret the response
// correctly, dropping hop-by-hop and connection-scoped headers (an allowlist
// excludes those by construction). Keys are canonicalized on the way out:
// "WWW-Authenticate" and "ETag" are NOT their own canonical forms, so writing
// them verbatim would produce a map that Header.Get can never find again.
func passthroughHeaders(h http.Header) http.Header {
	out := http.Header{}
	for _, k := range passthroughHeaderNames {
		if v := h.Values(k); len(v) > 0 {
			out[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
	}
	for k, vs := range h {
		lk := strings.ToLower(k)
		for _, p := range passthroughHeaderPrefixes {
			if strings.HasPrefix(lk, p) {
				out[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
				break
			}
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
