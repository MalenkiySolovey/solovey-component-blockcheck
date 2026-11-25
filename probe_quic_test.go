package blockcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
)

func TestQUICAndHTTP3ObserveSeparateStages(t *testing.T) {
	cert, roots := fixtureTLSCertificate(t)
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	var requests, responseStatus atomic.Int32
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			requests.Add(1)
			if req.ProtoMajor != 3 || req.Method != http.MethodHead || req.URL.Path != "/" {
				t.Errorf("unexpected request: %s %s %s", req.Proto, req.Method, req.URL.Path)
			}
			status := int(responseStatus.Load())
			if status == http.StatusFound {
				w.Header().Set("Location", "/not-requested")
			}
			w.WriteHeader(status)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(udp) }()
	defer func() { _ = server.Close(); <-done }()
	for _, tc := range []struct {
		name     string
		probe    Probe
		host     string
		response int
		stage    Stage
		status   Code
		requests int32
		verified bool
	}{
		{"handshake", QUIC, "fixture.example", 0, StageQUIC, OK, 0, true},
		{"http3", HTTP3, "fixture.example", 204, StageHTTP, HTTPResponse, 1, true},
		{"no redirect", HTTP3, "fixture.example", 302, StageHTTP, HTTPResponse, 1, true},
		{"wrong name", HTTP3, "other.example", 0, StageCertificate, CertificateInvalid, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), ProbeBudget)
			defer cancel()
			conn, err := net.DialUDP("udp4", nil, udp.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			before := requests.Load()
			responseStatus.Store(int32(tc.response)) // #nosec G115 -- fixed test statuses, all below 600.
			cfg := quicTLSConfig(tc.host)
			cfg.RootCAs = roots
			row := Result{Cell: Cell{Probe: tc.probe}}
			probeQUIC(ctx, &row, conn, cfg)
			if row.Stage != tc.stage || row.Status != tc.status || row.HTTPStatus != tc.response || row.TLSVerified != tc.verified || requests.Load()-before != tc.requests {
				t.Fatalf("unexpected QUIC observation: %+v (requests: %d)", row, requests.Load()-before)
			}
			if tc.verified && row.TLSVersion != "TLS 1.3" {
				t.Fatalf("wrong QUIC TLS version: %q", row.TLSVersion)
			}
		})
	}
}

func TestQUICRequiresAnAdmittedDatagramPath(t *testing.T) {
	component, catalog, req, path := fixture(t, Outbound, HTTP3)
	path.DialTCP = func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error) {
		t.Error("QUIC fell back to TCP")
		return nil, SocketEvidence{}, nil
	}
	row := runFixture(t, component, catalog, req, path).Results[0]
	if row.Status != Unsupported || row.Reason != string(ErrNoProbeCapability) || row.Proof != nil {
		t.Fatalf("unavailable datagram path: %+v", row)
	}
	path.DialUDP = func(_ context.Context, destination netip.AddrPort) (net.Conn, SocketEvidence, error) {
		if destination != netip.AddrPortFrom(fixtureAddr, 443) {
			t.Errorf("dial was not pinned to admitted endpoint: %v", destination)
		}
		return nil, SocketEvidence{}, ErrTargetRejected
	}
	row = runFixture(t, component, catalog, req, path).Results[0]
	if row.Status != Rejected || row.Stage != StageUDP || row.Proof != nil {
		t.Fatalf("UDP path rejected the destination: %+v", row)
	}
}

func TestQUICDeadlineWithoutAResponse(t *testing.T) {
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	conn, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	row := Result{Cell: Cell{Probe: HTTP3}}
	cfg := quicTLSConfig("fixture.example")
	cfg.RootCAs = x509.NewCertPool()
	probeQUIC(ctx, &row, conn, cfg)
	finding := interpretProbe(row)
	if row.Stage != StageQUIC || row.Status != Timeout || row.TLSVerified || row.HTTPStatus != 0 || finding == nil || finding.Code != "quic_handshake_incomplete" {
		t.Fatalf("no response is not a positive QUIC observation: %+v %v", row, finding)
	}
}
