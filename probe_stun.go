package blockcheck

import (
	"bytes"
	"cmp"
	"context"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

const stunHeaderBytes = 20
const maxSTUNResponseBytes = 1024

func probeSTUN(ctx context.Context, row *Result, conn net.Conn) {
	row.Stage = StageSTUN
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		row.Status, row.Reason = Unobservable, "stun_request_unavailable"
		return
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(ProbeBudget)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		stunDeadlineError(ctx, row)
		return
	}
	var buffer [maxSTUNResponseBytes + 1]byte
	// Retransmit on silence to tolerate UDP loss. Only this transaction on
	// the admitted socket can supply evidence; never follow a server redirect.
	for _, window := range [...]time.Duration{time.Second, 3 * time.Second} {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		if n, err := conn.Write(request.Raw); n != len(request.Raw) || err != nil {
			row.Status = classify(cmp.Or(ctx.Err(), err), ProtocolError)
			return
		}
		if err := conn.SetReadDeadline(earlierDeadline(deadline, time.Now().Add(window))); err != nil {
			stunDeadlineError(ctx, row)
			return
		}
		for range 8 {
			n, err := conn.Read(buffer[:])
			if err != nil {
				status := classify(cmp.Or(ctx.Err(), err), ProtocolError)
				if status == Timeout && ctx.Err() == nil {
					break
				}
				row.Status = status
				return
			}
			packet := buffer[:n]
			if !stun.IsMessage(packet) || !bytes.Equal(packet[8:stunHeaderBytes], request.TransactionID[:]) {
				continue
			}
			row.Status, row.Reason = stunBindingResult(packet)
			return
		}
	}
	row.Status = classify(ctx.Err(), Timeout)
}

func stunDeadlineError(ctx context.Context, row *Result) {
	if err := ctx.Err(); err != nil {
		row.Status = classify(err, Timeout)
		return
	}
	row.Status, row.Reason = Unsupported, "transport_deadline_unavailable"
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func stunBindingResult(packet []byte) (Code, string) {
	message := new(stun.Message)
	if len(packet) < stunHeaderBytes || len(packet) > maxSTUNResponseBytes || packet[0]&0xc0 != 0 || stun.Decode(packet, message) != nil ||
		int(message.Length) != len(packet)-stunHeaderBytes ||
		message.Contains(stun.AttrFingerprint) && stun.Fingerprint.Check(message) != nil {
		return ProtocolError, "stun_invalid_response"
	}
	switch message.Type {
	case stun.BindingError:
		var failure stun.ErrorCodeAttribute
		if failure.GetFrom(message) == nil && failure.Code >= 300 && failure.Code <= 699 {
			return ProtocolError, "stun_binding_error"
		}
	case stun.BindingSuccess:
		// Validate but do not retain or expose the reflected client address.
		var address stun.XORMappedAddress
		if address.GetFrom(message) == nil && address.Port != 0 {
			return OK, ""
		}
	}
	return ProtocolError, "stun_invalid_response"
}
