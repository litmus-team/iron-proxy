package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelOuterTLS(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fixture.Close()
	cert := fixture.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "proxy.crt")
	keyFile := filepath.Join(dir, "proxy.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, time.Hour)
	require.NoError(t, err)
	p := New(Options{CertCache: cache, TunnelAddr: "127.0.0.1:0", TunnelTLSCert: certFile, TunnelTLSKey: keyFile, Logger: testLogger(), Pipeline: transform.NewPipelineHolder(transform.NewPipeline(nil, transform.BodyLimits{}, testLogger()))})
	ln, err := p.newTunnelListener()
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go p.handleTunnel(c)
		}
	}()
	var upstreamCalls atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-only" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write(b)
	}))
	upstreamCert, err := cache.GetOrCreate("localhost")
	require.NoError(t, err)
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{*upstreamCert}, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	defer upstream.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	roots.AddCert(caCert)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(caCert)
	p.transport.TLSClientConfig.RootCAs = upstreamRoots
	origin := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
	proxyURL, err := url.Parse("https://" + ln.Addr().String())
	require.NoError(t, err)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, origin, bytes.NewBufferString("synthetic-sensitive-body"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer synthetic-only")
	resp, err := client.Do(req)
	require.NoError(t, err)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "synthetic-sensitive-body", string(b))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	if os.Getenv("IRON_PROXY_TEST_CLIENTS") == "1" {
		bundle := filepath.Join(dir, "clients.pem")
		require.NoError(t, os.WriteFile(bundle, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...), 0600))
		cases := []struct {
			name string
			args []string
		}{
			{"curl", []string{"curl", "--silent", "--show-error", "--fail", "--noproxy", "", "--proxy", proxyURL.String(), "--proxy-cacert", bundle, "--cacert", bundle, "-H", "Authorization: Bearer synthetic-only", "--data-binary", "synthetic-sensitive-body", origin}},
			{"requests", []string{os.Getenv("IRON_PROXY_TEST_PYTHON"), "-c", "import requests,sys;s=requests.Session();s.trust_env=False;r=s.post(sys.argv[1],data='synthetic-sensitive-body',headers={'Authorization':'Bearer synthetic-only'},proxies={'https':sys.argv[2]},verify=sys.argv[3],timeout=10);r.raise_for_status();print(r.text,end='')", origin, proxyURL.String(), bundle}},
			{"Node", []string{"node", "-e", `const https=require('https'),fs=require('fs');const{HttpsProxyAgent}=require(process.argv[1]);const ca=fs.readFileSync(process.argv[4]);const req=https.request(process.argv[2],{method:'POST',agent:new HttpsProxyAgent(process.argv[3],{ca}),ca,headers:{Authorization:'Bearer synthetic-only','Content-Length':24}},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{if(r.statusCode!==200)process.exitCode=1;else process.stdout.write(b)})});req.on('error',()=>process.exitCode=1);req.end('synthetic-sensitive-body')`, os.Getenv("IRON_PROXY_TEST_NODE_AGENT"), origin, proxyURL.String(), bundle}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, tc.args[0], tc.args[1:]...).CombinedOutput()
				require.NoError(t, err, string(out))
				require.Equal(t, "synthetic-sensitive-body", string(out))
			})
		}
	}
	// Untrusted clients cannot reach HTTP handling, and plaintext has no fallback.
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12})
	require.Error(t, err)
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, raw.SetDeadline(time.Now().Add(time.Second)))
	_, err = raw.Write([]byte("POST http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 4\r\n\r\nTEST"))
	require.NoError(t, err)
	_, err = http.ReadResponse(bufio.NewReader(raw), nil)
	require.Error(t, err)
	require.NoError(t, raw.Close())
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	require.Error(t, err)
	expected := int32(1)
	if os.Getenv("IRON_PROXY_TEST_CLIENTS") == "1" {
		expected = 4
	}
	require.Equal(t, expected, upstreamCalls.Load())
}

func TestTunnelTLSFailsClosedOnCertificateErrors(t *testing.T) {
	cases := []struct{ name, cert, key string }{
		{"missing_key", "/missing/cert", ""},
		{"missing_cert", "", "/missing/key"},
		{"missing_files", "/missing/cert", "/missing/key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Options{TunnelAddr: "127.0.0.1:0", TunnelTLSCert: tc.cert, TunnelTLSKey: tc.key, Logger: testLogger()})
			ln, err := p.newTunnelListener()
			require.Error(t, err)
			require.Nil(t, ln)
		})
	}
}

func TestTunnelOuterTLSDefaultOff(t *testing.T) {
	p := New(Options{TunnelAddr: "127.0.0.1:0", Logger: testLogger()})
	ln, err := p.newTunnelListener()
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	_, plain := ln.(*net.TCPListener)
	require.True(t, plain)
}
