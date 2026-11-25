package blockcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/pion/stun/v3"
)

func TestSTUNBindingResponseRequiresMatchingTransactionAndRetries(t *testing.T) {
	for _, fixture := range []struct {
		network string
		address string
		port    uint16
		family  Family
	}{
		{"udp4", "127.0.0.1", 3478, IPv4},
		{"udp6", "::1", 19302, IPv6},
	} {
		t.Run(fixture.network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), ProbeBudget)
			defer cancel()
			peer, err := net.ListenUDP(fixture.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(fixture.address), 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			deadline, _ := ctx.Deadline()
			if err := peer.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- replyAfterSTUNRetry(peer) }()
			publicTarget := fixtureAddr
			if fixture.family == IPv6 {
				publicTarget = netip.MustParseAddr("2001:4860::1")
			}
			target := Target{Host: publicTarget.String(), Port: fixture.port}
			path := Path{DialUDP: func(_ context.Context, destination netip.AddrPort) (net.Conn, SocketEvidence, error) {
				if destination != netip.AddrPortFrom(publicTarget, fixture.port) {
					t.Errorf("probe tried another destination: %v", destination)
					return nil, SocketEvidence{}, ErrTargetRejected
				}
				conn, err := net.DialUDP(fixture.network, nil, peer.LocalAddr().(*net.UDPAddr))
				return conn, SocketEvidence{}, err
			}}
			row := Result{Cell: Cell{Probe: STUN}}
			performProbe(ctx, &row, target, path, fixture.family, func(address netip.Addr) bool { return address == publicTarget })
			if row.Stage != StageSTUN || row.Status != OK || row.AddressFamily != fixture.family || row.TLSVerified || row.HTTPStatus != 0 {
				t.Fatalf("unexpected STUN observation: %+v", row)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(row)
			if err != nil || bytes.Contains(data, []byte("192.0.2.99")) || bytes.Contains(data, []byte("2001:db8::99")) {
				t.Fatalf("reflected address leaked: %s (%v)", data, err)
			}
		})
	}
}

func replyAfterSTUNRetry(peer *net.UDPConn) error {
	var buffer [128]byte
	var transaction [stun.TransactionIDSize]byte
	for i := range 2 {
		n, src, err := peer.ReadFromUDPAddrPort(buffer[:])
		if err != nil {
			return err
		}
		request := new(stun.Message)
		if stun.Decode(buffer[:n], request) != nil || request.Type != stun.BindingRequest {
			return errors.New("expected a STUN Binding request")
		}
		replyID := request.TransactionID
		if i == 0 {
			transaction = replyID
			replyID[0] ^= 128
		} else if transaction != replyID {
			return errors.New("retry changed the STUN transaction")
		}
		address := net.ParseIP("192.0.2.99")
		if src.Addr().Is6() {
			address = net.ParseIP("2001:db8::99")
		}
		response, err := stun.Build(stun.NewTransactionIDSetter(replyID), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: address, Port: 41541}, stun.Fingerprint)
		if err != nil {
			return err
		}
		if _, err := peer.WriteToUDPAddrPort(response.Raw, src); err != nil {
			return err
		}
	}
	return nil
}

func TestSTUNBindingErrorAndMalformedResponsesDoNotPass(t *testing.T) {
	valid := stun.MustBuild(stun.TransactionID, stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.ParseIP("192.0.2.99"), Port: 41541}, stun.Fingerprint).Raw
	badFingerprint := bytes.Clone(valid)
	badFingerprint[len(badFingerprint)-1] ^= 0x80
	for _, tc := range []struct {
		packet []byte
		reason string
	}{
		{stun.MustBuild(stun.TransactionID, stun.BindingError, stun.CodeTryAlternate).Raw, "stun_binding_error"},
		{stun.MustBuild(stun.TransactionID, stun.BindingSuccess).Raw, "stun_invalid_response"},
		{append(bytes.Clone(valid), 0), "stun_invalid_response"},
		{badFingerprint, "stun_invalid_response"},
	} {
		if status, reason := stunBindingResult(tc.packet); status != ProtocolError || reason != tc.reason {
			t.Fatalf("unexpected STUN failure: %s, %s (want %s)", status, reason, tc.reason)
		}
	}
}

func TestSTUNNeverUsesTCPAndHonorsCancellation(t *testing.T) {
	row := Result{Cell: Cell{Probe: STUN}}
	performProbe(t.Context(), &row, Target{Host: fixtureAddr.String(), Port: 3478}, Path{
		DialTCP: func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error) {
			t.Fatal("STUN fell back to TCP")
			return nil, SocketEvidence{}, nil
		},
	}, IPv4, func(netip.Addr) bool { return true })
	if row.Status != Unsupported || row.Reason != string(ErrNoProbeCapability) {
		t.Fatalf("missing UDP capability: %+v", row)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	requests := make(chan error, 1)
	go func() {
		var datagram [64]byte
		_, err := server.Read(datagram[:])
		cancel()
		requests <- err
	}()
	probeSTUN(ctx, &row, client)
	if err := <-requests; err != nil {
		t.Fatal(err)
	}
	if row.Status != Canceled || row.Stage != StageSTUN {
		t.Fatalf("canceled probe: %+v", row)
	}
}
