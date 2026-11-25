package blockcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

const chromeTLSProfile = "chrome-133"

// This probe uses a pinned Chrome TLS profile, not a browser or Chrome's
// HTTP/2 fingerprint. Both ALPN branches reuse the already admitted stream.
func probeChromeHTTPS(ctx context.Context, row *Result, stream net.Conn, host string, roots *x509.CertPool) {
	row.Stage, row.TLSProfile = StageTLS, chromeTLSProfile
	secure := utls.UClient(stream, &utls.Config{ServerName: host, RootCAs: roots}, utls.HelloChrome_133)
	if err := secure.HandshakeContext(ctx); err != nil {
		row.Status = classify(err, TLSFailed)
		var verification *utls.CertificateVerificationError
		if row.Status == CertificateInvalid || errors.As(err, &verification) {
			row.Stage, row.Status = StageCertificate, CertificateInvalid
		}
		return
	}
	state := secure.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		row.Stage, row.Status = StageCertificate, CertificateInvalid
		return
	}
	row.TLSVerified, row.TLSVersion = true, tls.VersionName(state.Version)
	switch state.NegotiatedProtocol {
	case "h2":
		probeChromeHTTP2(ctx, row, secure, host)
	case "", "http/1.1":
		probeHTTP(row, host, secure)
	default:
		row.Stage, row.Status = StageHTTP, ProtocolError
	}
}

type http2BudgetConn struct {
	net.Conn
	incoming io.LimitedReader
}

func (c *http2BudgetConn) Read(p []byte) (int, error) { return c.incoming.Read(p) }

func probeChromeHTTP2(ctx context.Context, row *Result, conn net.Conn, host string) {
	row.Stage = StageHTTP
	// Bound the peer's control frames as well as the decoded response headers.
	bounded := &http2BudgetConn{Conn: conn, incoming: io.LimitedReader{R: conn, N: 2 * maxHeaderBytes}}
	transport := http2.Transport{DisableCompression: true, MaxHeaderListSize: maxHeaderBytes}
	client, err := transport.NewClientConn(bounded)
	if err != nil {
		row.Status = classify(err, ProtocolError)
		return
	}
	defer client.Close()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	request := &http.Request{Method: http.MethodHead, URL: &url.URL{Scheme: "https", Host: host, Path: "/"}}
	response, err := client.RoundTrip(request.WithContext(ctx))
	if err != nil {
		row.Status = classify(err, ProtocolError)
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 {
		row.Status = ProtocolError
		return
	}
	row.Status, row.HTTPStatus, row.HTTPProtocol = HTTPResponse, response.StatusCode, "HTTP/2"
}
