package blockcheck

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestICMPEchoUsesOnlyTheSelectedCapability(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.2")
	socket := SocketEvidence{Interface: "fixture", OutsidePanel: true}
	for _, tc := range []struct {
		name     string
		provider bool
		admitted bool
		observed SocketEvidence
		err      error
		want     Code
		sent     bool
	}{
		{name: "no capability", admitted: true, want: Unsupported},
		{name: "target policy", provider: true, want: Rejected},
		{name: "confirmed", provider: true, admitted: true, observed: socket, want: OK, sent: true},
		{name: "capless socket denied", provider: true, admitted: true, err: ErrICMPEchoUnavailable, want: Unsupported},
		{name: "send failed", provider: true, admitted: true, err: ErrICMPEchoNotSent, want: Unobservable},
		{name: "missing baseline evidence", provider: true, admitted: true, want: Unobservable},
		{name: "no reply on observed path", provider: true, admitted: true, observed: socket, err: context.DeadlineExceeded, want: Timeout, sent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := Result{Cell: Cell{Probe: ICMP}}
			calls := 0
			path := Path{Evidence: PathEvidence{Mode: HostBaseline}}
			unexpected := func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error) {
				t.Fatal("Echo used a TCP or UDP diagnostic dialer")
				return nil, SocketEvidence{}, nil
			}
			path.DialTCP, path.DialUDP = unexpected, unexpected
			if tc.provider {
				path.EchoICMP = func(_ context.Context, remote netip.Addr) (SocketEvidence, error) {
					calls++
					if remote != addr {
						t.Fatalf("Echo target = %v, want %v", remote, addr)
					}
					return tc.observed, tc.err
				}
			}
			performProbe(context.Background(), &row, Target{Host: addr.String()}, path, IPv4, func(netip.Addr) bool { return tc.admitted })
			if row.Status != tc.want || (row.Stage == StageICMP) != tc.sent || (row.Socket != nil) != tc.sent || (row.AttemptedAddress != "") != tc.sent || calls > 1 ||
				(calls == 1) != (tc.provider && tc.admitted) {
				t.Fatalf("result = %+v, calls = %d", row, calls)
			}
			finding := interpretProbe(row)
			if tc.want == Timeout {
				if finding == nil || finding.Code != "icmp_echo_incomplete" || finding.Confidence != "observed" {
					t.Fatalf("finding = %+v", finding)
				}
			} else if finding != nil {
				t.Fatalf("unexpected finding = %+v", finding)
			}
		})
	}
}
