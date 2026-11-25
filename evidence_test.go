package blockcheck

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"fixture.example"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

func TestExactTLSVersionWithVerification(t *testing.T) {
	cert, roots := fixtureTLSCertificate(t)
	for _, tc := range []struct {
		name  string
		probe Probe
		max   uint16
		host  string
		stage Stage
		code  Code
		want  uint16
	}{
		{"1.2 exact with newer server", TLS12, tls.VersionTLS13, "fixture.example", StageTLS, "", tls.VersionTLS12},
		{"1.3 exact", TLS13, tls.VersionTLS13, "fixture.example", StageTLS, "", tls.VersionTLS13},
		{"reject downgrade", TLS13, tls.VersionTLS12, "fixture.example", StageTLS, TLSFailed, 0},
		{"reject wrong name", TLS13, tls.VersionTLS13, "other.example", StageCertificate, CertificateInvalid, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tc.max})
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(ctx) }()
			cfg := probeTLSConfig(tc.probe, tc.host)
			cfg.RootCAs = roots
			row := Result{}
			secure := handshake(ctx, &row, client, cfg)
			if row.Stage != tc.stage || row.Status != tc.code {
				t.Fatalf("unexpected stage: %+v", row)
			}
			if tc.want == 0 {
				if secure != nil || row.TLSVerified {
					t.Fatal("invalid handshake accepted")
				}
				return
			}
			if err := <-done; err != nil || secure == nil || !row.TLSVerified || row.TLSVersion != tls.VersionName(tc.want) {
				t.Fatalf("wrong negotiated or verified version: %+v %v", row, err)
			}
		})
	}
}

func TestBoundedTransferEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		size int
		body string
		read int64
		want Code
		why  string
	}{
		{"complete", 200, 8, "response", 8, HTTPResponse, ""},
		{"truncated", 200, 12, "response", 8, StreamClosed, "transfer_interrupted"},
		{"bounded", 200, maxTransferBytes + 1, strings.Repeat("x", maxTransferBytes+1), maxTransferBytes, HTTPResponse, ""},
		{"http failure", 503, 5, "error", 0, HTTPResponse, "http_error_response"},
		{"empty", 200, 0, "", 0, HTTPResponse, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cat, req, path := fixture(t, Outbound, HTTPData)
			path.DialTCP = func(_ context.Context, target netip.AddrPort) (net.Conn, SocketEvidence, error) {
				if target != netip.AddrPortFrom(fixtureAddr, 80) {
					t.Errorf("unexpected socket: %v", target)
				}
				client, peer := net.Pipe()
				go func() {
					defer peer.Close()
					request, err := http.ReadRequest(bufio.NewReader(peer))
					if err != nil || request.Method != http.MethodGet || request.URL.Path != "/" || request.Header.Get("Accept-Encoding") != "identity" {
						t.Error("expected a bounded GET probe")
						return
					}
					header := "HTTP/1.1 " + strconv.Itoa(tc.code) + " Fixture\r\nContent-Length: " + strconv.Itoa(tc.size) + "\r\n\r\n"
					_, _ = io.WriteString(peer, header+tc.body)
				}()
				return client, SocketEvidence{}, nil
			}
			row := runFixture(t, c, cat, req, path).Results[0]
			if row.Status != tc.want || row.HTTPStatus != tc.code || row.BodyBytes != tc.read {
				t.Fatalf("wrong transfer result: %+v", row)
			}
			if (row.Proof != nil) != (tc.read > 0 && tc.want == HTTPResponse) {
				t.Fatalf("false positive or missing observation: %+v", row)
			}
			if tc.why != "" && (row.Interpretation == nil || row.Interpretation.Code != tc.why || row.Interpretation.Confidence != "observed") {
				t.Fatalf("missing precise stage finding: %+v", row)
			}
			if tc.read == maxTransferBytes && row.Reason != "transfer_sample_limit" {
				t.Fatal("bounded sample treated as full transfer")
			}
		})
	}
}

func TestDeepPlanAndLikeForLikeTLSContrast(t *testing.T) {
	_, catalog, req, _ := fixture(t, Outbound, DNS, HTTPS, TLS13, ICMP)
	req.Cells = []Cell{{0, HTTPS}, {0, TLS13}}
	plan, progress, _, err := prepareSuite(catalog, SuiteRequest{RunRequest: req, Depth: Deep})
	if err != nil || progress.TotalProbes != 4 || !slices.Equal(plan[0].cells, []Cell{{0, HTTPS}, {0, TLS12}, {0, HTTPSData}, {0, TLS13}}) {
		t.Fatalf("deep selection duplicated or changed saved probes: %+v %v", plan, err)
	}
	if _, _, _, err := prepareSuite(catalog, SuiteRequest{RunRequest: req, Depth: "invalid"}); err == nil {
		t.Fatal("unsupported diagnostic depth accepted")
	}
	a := Result{Cell: Cell{0, TLS12}, Status: OK, TLSVerified: true, Stage: StageTLS, address: fixtureAddr}
	b := Result{Cell: Cell{0, TLS13}, Status: Timeout, Stage: StageTLS, address: fixtureAddr}
	var pairs tlsPairs
	if len(pairs.observe([]Result{a})) != 0 {
		t.Fatal("isolated result became a contrast")
	}
	contrasts := pairs.observe([]Result{b})
	if len(contrasts) != 1 || contrasts[0].Confidence != "indicative" {
		t.Fatalf("unexpected contrast: %+v", contrasts)
	}
	b.address = netip.MustParseAddr("192.0.2.11")
	if len(pairs.observe([]Result{a, b})) != 0 {
		t.Fatal("different endpoint became a TLS version contrast")
	}
	if data, err := json.Marshal(a); err != nil || strings.Contains(string(data), fixtureAddr.String()) {
		t.Fatalf("comparison address leaked: %s (%v)", data, err)
	}
}
