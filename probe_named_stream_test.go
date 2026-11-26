package blockcheck

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestNamedStreamObservesEgressOnlyForApplicationProbe(t *testing.T) {
	const host = "fixture.example"
	address := netip.MustParseAddr("8.8.4.4")
	permit := func(addr netip.Addr) bool { return addr == address }
	for _, tc := range []struct {
		name     string
		probe    Probe
		routeErr error
		status   Code
		web      bool
	}{
		{"http", HTTP, nil, HTTPResponse, true},
		{"rejected-after-tunnel", HTTP, ErrTargetRejected, Rejected, false},
		{"bare-tcp", TCP, nil, Unsupported, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			answered := make(chan struct{})
			path := Path{
				Evidence: PathEvidence{Mode: Panel},
				Resolve: func(context.Context, string, Family, Probe) (Resolution, error) {
					return Resolution{Addresses: []netip.Addr{address}, Context: "test-active-dns"}, nil
				},
				DialNamedStream: func(_ context.Context, h string, dst netip.AddrPort) (net.Conn, func() (SocketEvidence, error), error) {
					called = true
					if h != host || dst != netip.AddrPortFrom(address, 80) {
						t.Fatalf("probe passed an unadmitted hostname or address: %s %s", h, dst)
					}
					client, wire := net.Pipe()
					go func() {
						defer wire.Close()
						request, err := http.ReadRequest(bufio.NewReader(wire))
						if err != nil || request.Host != host || request.Method != http.MethodHead {
							return
						}
						close(answered)
						if tc.web {
							_, _ = io.WriteString(wire, "HTTP/1.1 204 No Content\r\n\r\n")
						}
					}()
					return client, func() (SocketEvidence, error) {
						select {
						case <-answered:
						default:
							t.Fatal("route observed before sending the probe")
						}
						if tc.routeErr != nil {
							return SocketEvidence{}, tc.routeErr
						}
						return SocketEvidence{Egress: "admitted-leaf"}, nil
					}, nil
				},
			}
			row := Result{Cell: Cell{Probe: tc.probe}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			performProbe(ctx, &row, Target{Host: host}, path, Any, permit)
			if row.Status != tc.status || called != (tc.probe != TCP) {
				t.Fatalf("unexpected observation: %+v", row)
			}
			if tc.web && (row.HTTPStatus != http.StatusNoContent || row.Socket == nil || row.Socket.Egress != "admitted-leaf") {
				t.Fatalf("missing HTTP or egress report: %+v", row)
			}
			if tc.routeErr != nil && (row.Stage != StageTCP || row.Socket != nil || row.Reason != string(ErrTargetRejected)) {
				t.Fatalf("late routing error was misreported as endpoint failure: %+v", row)
			}
		})
	}
}
