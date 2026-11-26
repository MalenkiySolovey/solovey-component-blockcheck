package blockcheck

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hostports "github.com/MalenkiySolovey/solovey-host/componenthost"
	"github.com/MalenkiySolovey/solovey-host/componenthost/health"
	"github.com/MalenkiySolovey/solovey-host/hostref"
	"github.com/MalenkiySolovey/solovey-host/operationref"
)

var fixtureAddr = netip.MustParseAddr("192.0.2.10")

func fixture(t *testing.T, mode Mode, probes ...Probe) (*Component, Catalog, RunRequest, Path) {
	t.Helper()
	c := &Component{}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := c.Start(t.Context(), hostports.Ports{Host: hostref.Local()}); err != nil {
		t.Fatal(err)
	}
	cat := Catalog{Schema: CatalogSchema, Groups: []Group{{ID: "fixture", Name: "Fixture", Targets: []Target{{Name: "Host", Host: "fixture.example", Probes: probes}}}}}
	ref, generation := "target", "core-generation"
	if mode == HostBaseline {
		ref, generation = "", ""
	}
	path := Path{Evidence: PathEvidence{Host: hostref.Local(), Mode: mode, Scope: "fixture", Context: "operator-context", Generation: generation},
		Current: func(context.Context) error { return nil },
		Resolve: func(context.Context, string, Family, Probe) (Resolution, error) {
			return Resolution{Addresses: []netip.Addr{fixtureAddr}, Context: "fixture-resolver"}, nil
		}}
	return c, cat, RunRequest{GroupID: "fixture", CatalogRevision: cat.Revision(), Path: PathSelection{Mode: mode, Ref: ref}, Family: IPv4}, path
}

func fixtureProvider(path Path) Provider {
	return ProviderFunc(func(context.Context, hostref.Ref, PathSelection) (Path, error) { return path, nil })
}

func runFixture(t *testing.T, c *Component, cat Catalog, req RunRequest, path Path) Report {
	t.Helper()
	result, err := c.Run(t.Context(), hostref.Local(), cat, req, fixtureProvider(path), func(ip netip.Addr) bool { return ip == fixtureAddr })
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestProbeDoesNotDialOnPrivateAnswerEvenInOtherFamily(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, TCP)
	path.Resolve = func(context.Context, string, Family, Probe) (Resolution, error) {
		return Resolution{Addresses: []netip.Addr{fixtureAddr, netip.MustParseAddr("fd00::2")}, Context: "verified-context"}, nil
	}
	path.DialTCP = func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error) {
		t.Fatal("mixed answers must not dial")
		return nil, SocketEvidence{}, nil
	}
	if row := runFixture(t, c, cat, req, path).Results[0]; row.Status != Rejected || row.Proof != nil {
		t.Fatalf("invalid evidence: %+v", row)
	}
}

func TestBaselineRequiresResolverAndSocketExclusionSeparately(t *testing.T) {
	c, cat, req, path := fixture(t, HostBaseline, DNS, TCP)
	var dials int
	path.DialTCP = func(_ context.Context, dst netip.AddrPort) (net.Conn, SocketEvidence, error) {
		dials++
		if dst != netip.AddrPortFrom(fixtureAddr, 443) {
			t.Fatalf("dial changed approved literal: %s", dst)
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, SocketEvidence{Interface: "eth1"}, nil
	}
	report := runFixture(t, c, cat, req, path)
	for _, row := range report.Results {
		if row.Status != Unobservable || row.Reason != string(ErrBaselineUnobservable) || row.Proof != nil {
			t.Fatalf("accepted unauthenticated baseline: %+v", row)
		}
	}
	if dials != 0 {
		t.Fatal("destination dial after unqualified resolver")
	}
	path.Resolve = func(context.Context, string, Family, Probe) (Resolution, error) {
		return Resolution{Addresses: []netip.Addr{fixtureAddr}, Context: "fixture-dns", Socket: SocketEvidence{Interface: "eth1", OutsidePanel: true}}, nil
	}
	report = runFixture(t, c, cat, req, path)
	if dns, tcp := report.Results[0], report.Results[1]; dns.Status != DNSResponse || dns.DNSSocket == nil ||
		!health.ValidEvidence("fixture", dns.Proof) || tcp.Status != Unobservable || tcp.Proof != nil || dials != 1 {
		t.Fatalf("resolver and destination evidence conflated: %+v", report.Results)
	}
	if redacted := report.Redacted(); redacted.Evidence.Context != "" || redacted.Results[0].DNSSocket != nil || report.Results[0].DNSSocket == nil {
		t.Fatal("redaction lost or leaked evidence details")
	}
}

func TestDNSNegativeResponseAndWrongTransportAreNotProof(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, DoT, DNS)
	code := uint16(3)
	path.Resolve = func(context.Context, string, Family, Probe) (Resolution, error) {
		return Resolution{Context: "resolver", Transport: "dns-udp", RCode: &code}, nil
	}
	report := runFixture(t, c, cat, req, path)
	if dot, dns := report.Results[0], report.Results[1]; dot.Status != Unobservable || dot.Proof != nil || dns.Status != DNSResponse ||
		dns.Proof != nil || dns.DNSRCode == nil || *dns.DNSRCode != 3 {
		t.Fatalf("incorrect DNS observation: %+v", report.Results)
	}
}

func TestBaselineDistinguishesUnsupportedDNSFromMissingObservation(t *testing.T) {
	c, cat, req, path := fixture(t, HostBaseline, DNS, DoH)
	path.Resolve = func(_ context.Context, _ string, _ Family, probe Probe) (Resolution, error) {
		if probe == DoH {
			return Resolution{}, ErrResolverUnsupported
		}
		return Resolution{}, ErrBaselineUnobservable
	}
	result := runFixture(t, c, cat, req, path).Results
	if dns, doh := result[0], result[1]; dns.Status != Unobservable || dns.Reason != string(ErrBaselineUnobservable) ||
		doh.Status != Unsupported || doh.Reason != string(ErrResolverUnsupported) || doh.Proof != nil {
		t.Fatalf("unsupported Host resolver transport conflated with missing path evidence: %+v", result)
	}
}

func TestConfiguredDNSAndProxyAcknowledgementAreNotEndpointEvidence(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, DNSUDP, TCP)
	code := uint16(0)
	path.Resolve = func(context.Context, string, Family, Probe) (Resolution, error) {
		return Resolution{Addresses: []netip.Addr{fixtureAddr}, Context: "explicit-resolver", ConfiguredTransport: "dns-udp", RCode: &code}, nil
	}
	path.DialTCP = func(_ context.Context, target netip.AddrPort) (net.Conn, SocketEvidence, error) {
		if target != netip.AddrPortFrom(fixtureAddr, 443) {
			t.Fatalf("changed dial target: %v", target)
		}
		client, proxy := net.Pipe()
		_ = proxy.Close()
		return client, SocketEvidence{ProxyAccepted: true}, nil
	}
	rows := runFixture(t, c, cat, req, path).Results
	dns, tcp := rows[0], rows[1]
	if dns.Status != Unobservable || dns.Reason != "dns_transport_not_observed" || dns.DNSTransport != "" ||
		dns.DNSConfiguredTransport != "dns-udp" || dns.AnswerCount != 1 || dns.Proof != nil {
		t.Fatalf("configured UDP treated as observed: %+v", dns)
	}
	if tcp.Status != Unobservable || tcp.Reason != "proxy_connect_not_endpoint_proof" || tcp.Socket == nil || !tcp.Socket.ProxyAccepted || tcp.Proof != nil {
		t.Fatalf("proxy acknowledgement treated as endpoint proof: %+v", tcp)
	}
}

func TestProxyStreamCanObserveHTTPWithoutProvingEndpointTCP(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, TCP, HTTP)
	path.DialTCP = func(_ context.Context, target netip.AddrPort) (net.Conn, SocketEvidence, error) {
		client, proxy := net.Pipe()
		if target.Port() == 80 {
			go func() {
				defer proxy.Close()
				request, err := http.ReadRequest(bufio.NewReader(proxy))
				if err != nil || request.Method != http.MethodHead || request.Host != "fixture.example" {
					t.Error("unexpected HTTP request")
					return
				}
				_, _ = io.WriteString(proxy, "HTTP/1.1 204 No Content\r\n\r\n")
			}()
		} else {
			_ = proxy.Close()
		}
		return client, SocketEvidence{ProxyTransportOnly: true}, nil
	}
	rows := runFixture(t, c, cat, req, path).Results
	tcp, httpRow := rows[0], rows[1]
	if tcp.Status != Unobservable || tcp.Reason != "proxy_endpoint_tcp_not_observed" || tcp.Proof != nil ||
		tcp.Socket == nil || !tcp.Socket.ProxyTransportOnly || tcp.Socket.ProxyAccepted {
		t.Fatalf("lazy proxy dial presented as an endpoint or CONNECT observation: %+v", tcp)
	}
	if httpRow.Status != HTTPResponse || httpRow.HTTPStatus != 204 {
		t.Fatalf("actual HTTP response through lazy proxy stream lost: %+v", httpRow)
	}
}

func TestHTTPReportsFinalStatusAndNeverFollowsRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		status     int
		proof      bool
	}{
		{"ok", "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n", 204, true},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\n\r\n", 302, false},
		{"failure", "HTTP/1.1 503 Unavailable\r\n\r\n", 503, false},
		{"oversize", "HTTP/1.1 200 OK\r\nX-Excess: " + strings.Repeat("a", maxHeaderBytes) + "\r\n\r\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cat, req, path := fixture(t, Outbound, HTTP)
			var attempts int
			path.DialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, SocketEvidence, error) {
				attempts++
				if dst != netip.AddrPortFrom(fixtureAddr, 80) {
					t.Fatalf("unexpected destination: %v", dst)
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					request, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil || request.Method != http.MethodHead || request.Host != "fixture.example" || request.RequestURI != "/" {
						t.Error("unexpected HTTP request")
						return
					}
					_, _ = io.WriteString(server, tc.head)
				}()
				return client, SocketEvidence{Egress: "observed"}, nil
			}
			row := runFixture(t, c, cat, req, path).Results[0]
			if attempts != 1 || row.HTTPStatus != tc.status || (row.Proof != nil) != tc.proof ||
				(tc.status != 0 && row.Status != HTTPResponse) || (tc.status == 0 && row.Status != ProtocolError) {
				t.Fatalf("unexpected HTTP evidence (%d dials): %+v", attempts, row)
			}
		})
	}
}

func TestGenerationDriftDiscardsObservationAndComparison(t *testing.T) {
	c, cat, req, path := fixture(t, Panel, DNS)
	var checks atomic.Int32
	path.Current = func(context.Context) error {
		if checks.Add(1) > 1 {
			return ErrGenerationChanged
		}
		return nil
	}
	report := runFixture(t, c, cat, req, path)
	row := report.Results[0]
	if row.Status != Unobservable || row.Reason != string(ErrGenerationChanged) || row.Proof != nil ||
		row.AnswerDigest != "" || row.DNSContext != "" || Comparable(report, report) {
		t.Fatalf("stale evidence survived: %+v", row)
	}
}

func TestStopCancelsExactRunAndRejectsConcurrentExecution(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, DNS, TCP)
	entered := make(chan struct{})
	path.Resolve = func(ctx context.Context, _ string, _ Family, _ Probe) (Resolution, error) {
		close(entered)
		<-ctx.Done()
		return Resolution{}, ctx.Err()
	}
	done := make(chan Report, 1)
	go func() {
		r, err := c.Run(t.Context(), hostref.Local(), cat, req, fixtureProvider(path), func(netip.Addr) bool { return true })
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	if _, err := c.Run(t.Context(), hostref.Local(), cat, req, fixtureProvider(path), func(netip.Addr) bool { return true }); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent run admitted: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if len(result.Results) != 2 || result.Job.Outcome != operationref.OutcomeFailed || result.Job.CancelSupported ||
		result.Results[0].Status != Canceled || result.Results[1].Status != Canceled {
		t.Fatalf("stop did not cancel exact run: %+v", result)
	}
	if _, err := c.Run(t.Context(), hostref.Local(), cat, req, fixtureProvider(path), func(netip.Addr) bool { return true }); !errors.Is(err, ErrInactive) {
		t.Fatalf("disabled component admitted network work: %v", err)
	}
}
