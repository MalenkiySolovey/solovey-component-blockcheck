package blockcheck

import (
	"cmp"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func quicTLSConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}
}

func probeQUIC(ctx context.Context, row *Result, conn net.Conn, tlsConfig *tls.Config) {
	row.Stage = StageQUIC
	// The connected socket belongs to the chosen path. DialConn has no system
	// dialer, alternate endpoint, 0-RTT, or TCP fallback.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	session, err := quic.DialConn(ctx, conn, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: ProbeBudget, MaxIdleTimeout: ProbeBudget,
		MaxIncomingStreams: -1, MaxIncomingUniStreams: 3,
		InitialStreamReceiveWindow: maxHeaderBytes, MaxStreamReceiveWindow: maxHeaderBytes,
		InitialConnectionReceiveWindow: 4 * maxHeaderBytes, MaxConnectionReceiveWindow: 4 * maxHeaderBytes,
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		row.Status = classify(cmp.Or(ctx.Err(), err), QUICFailed)
		if row.Status == CertificateInvalid {
			row.Stage = StageCertificate
		}
		return
	}
	defer func() { _ = session.CloseWithError(0, "") }()
	state := session.ConnectionState().TLS
	row.TLSVerified, row.TLSVersion = len(state.VerifiedChains) != 0, tls.VersionName(state.Version)
	if row.Probe == QUIC {
		row.Status = OK
		return
	}
	row.Stage = StageHTTP
	transport := &http3.Transport{MaxResponseHeaderBytes: maxHeaderBytes, DisableCompression: true}
	// NewClientConn performs a single HTTP/3 request on the same authenticated
	// session; unlike a client it does not follow redirects.
	target := &url.URL{Scheme: "https", Host: net.JoinHostPort(tlsConfig.ServerName, "443"), Path: "/"}
	request := (&http.Request{Method: http.MethodHead, URL: target, Header: http.Header{}}).WithContext(ctx)
	response, err := transport.NewClientConn(session).RoundTrip(request)
	if err != nil {
		row.Status = classify(cmp.Or(ctx.Err(), err), ProtocolError)
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.ProtoMajor != 3 || response.StatusCode < 200 || response.StatusCode > 599 {
		row.Status = ProtocolError
		return
	}
	row.HTTPStatus, row.Status = response.StatusCode, HTTPResponse
}
