package blockcheck

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestChromeProfileAndProtocolOnWire(t *testing.T) {
	cert, roots := fixtureTLSCertificate(t)
	for _, tc := range []struct {
		name, host, protocol string
		h2, largeHeaders     bool
		status               int
		want                 Code
	}{
		{"verified HTTP/2", "fixture.example", "HTTP/2", true, false, 204, HTTPResponse},
		{"HTTP/1.1 redirect not followed", "fixture.example", "HTTP/1.1", false, false, 301, HTTPResponse},
		{"wrong certificate name", "other.example", "", true, false, 0, CertificateInvalid},
		{"oversized HTTP/2 response head", "fixture.example", "", true, true, 204, ProtocolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			hello := make(chan *tls.ClientHelloInfo, 1)
			requests := make(chan string, 1)
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protocol := r.Proto
				if r.ProtoMajor == 2 {
					protocol = "HTTP/2"
				}
				requests <- r.Method + " " + r.Host + r.URL.Path + " " + protocol
				if tc.largeHeaders {
					w.Header().Set("X-Fixture", strings.Repeat("a", 4*maxHeaderBytes))
				}
				if tc.status == 301 {
					w.Header().Set("Location", "https://not-contacted.invalid/")
				}
				w.WriteHeader(tc.status)
			}))
			peer.EnableHTTP2 = tc.h2
			peer.TLS = &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
				GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					hello <- info
					return nil, nil
				},
			}
			peer.StartTLS()
			defer peer.Close()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", peer.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			row := Result{Cell: Cell{Probe: HTTPSChrome}}
			probeChromeHTTPS(ctx, &row, conn, tc.host, roots)
			if row.Status != tc.want || row.TLSProfile != chromeTLSProfile || row.HTTPProtocol != tc.protocol {
				t.Fatalf("unexpected probe outcome: %+v", row)
			}
			select {
			case observed := <-hello:
				if observed.ServerName != tc.host || !slices.Equal(observed.SupportedProtos, []string{"h2", "http/1.1"}) ||
					!slices.Contains(observed.SupportedCurves, tls.X25519MLKEM768) || !slices.Contains(observed.CipherSuites, tls.TLS_RSA_WITH_AES_128_GCM_SHA256) {
					t.Fatalf("did not see the expected Chrome profile on wire: %+v", observed)
				}
			default:
				t.Fatal("no ClientHello observed")
			}
			if tc.want == CertificateInvalid {
				if row.Stage != StageCertificate || row.TLSVerified || len(requests) != 0 {
					t.Fatalf("unverified peer reached HTTP: %+v", row)
				}
				return
			}
			if row.Stage != StageHTTP || !row.TLSVerified || row.TLSVersion != "TLS 1.3" {
				t.Fatalf("missing verified TLS and HTTP evidence: %+v", row)
			}
			select {
			case request := <-requests:
				if tc.want == HTTPResponse && (request != "HEAD fixture.example/ "+tc.protocol || row.HTTPStatus != tc.status) {
					t.Fatalf("unexpected admitted wire request %q, result %+v", request, row)
				}
			default:
				t.Fatal("no HTTP request observed")
			}
			if len(hello) != 0 || len(requests) != 0 || (tc.want != HTTPResponse && row.HTTPStatus != 0) {
				t.Fatalf("second exchange or false HTTP success: %+v", row)
			}
		})
	}
}

func TestChromeProbeUsesOnlyAdmittedSocket(t *testing.T) {
	c, catalog, req, path := fixture(t, Outbound, HTTPSChrome)
	cert, _ := fixtureTLSCertificate(t)
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an untrusted endpoint received an HTTP request")
	}))
	peer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	peer.StartTLS()
	defer peer.Close()
	dials := 0
	path.DialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, SocketEvidence, error) {
		dials++
		if dst != netip.AddrPortFrom(fixtureAddr, 443) {
			t.Errorf("unexpected policy-checked destination: %s", dst)
		}
		client, err := (&net.Dialer{}).DialContext(ctx, "tcp", peer.Listener.Addr().String())
		return client, SocketEvidence{ProxyTransportOnly: true}, err
	}
	row := runFixture(t, c, catalog, req, path).Results[0]
	if dials != 1 || row.Stage != StageCertificate || row.Status != CertificateInvalid || row.Proof != nil || row.Socket == nil || !row.Socket.ProxyTransportOnly {
		t.Fatalf("probe bypassed, retried or misreported its path: dials=%d result=%+v", dials, row)
	}
}

func TestTLSClientProfileContrastRequiresMatchedEvidence(t *testing.T) {
	control := Result{Cell: Cell{0, TLS13}, TargetRef: "fixture", Stage: StageTLS, Status: OK,
		TLSVerified: true, TLSVersion: "TLS 1.3", DNSContext: "observed-dns", address: fixtureAddr}
	chrome := control
	chrome.Probe, chrome.TLSProfile, chrome.Status, chrome.TLSVerified, chrome.TLSVersion = HTTPSChrome, chromeTLSProfile, ConnectionReset, false, ""
	var pairs tlsPairs
	if got := pairs.observe([]Result{chrome}); len(got) != 0 {
		t.Fatalf("single failure became a client contrast: %+v", got)
	}
	if got := pairs.observe([]Result{control}); len(got) != 1 || got[0].Code != "tls_client_profile_difference" || got[0].Confidence != "indicative" {
		t.Fatalf("missing or overstated client contrast: %+v", got)
	}
	for _, change := range []func(*Result){
		func(r *Result) { r.address = netip.MustParseAddr("9.9.9.10") },
		func(r *Result) { r.Stage, r.Status = StageCertificate, CertificateInvalid },
		func(r *Result) { r.Stage, r.Status = StageHTTP, HTTPResponse },
		func(r *Result) { r.TLSProfile = "" },
		func(r *Result) { r.Socket = &SocketEvidence{Egress: "different"} },
	} {
		variation, pair := chrome, tlsPairs{}
		change(&variation)
		if got := pair.observe([]Result{variation, control}); len(got) != 0 {
			t.Fatalf("unmatched observations became a client contrast: %+v", got)
		}
	}
}
