package blockcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"

	"github.com/MalenkiySolovey/solovey-host/operationref"
)

const maxHeaderBytes = 16 << 10
const maxDNSAddresses = 64

func performProbe(ctx context.Context, row *Result, target Target, path Path, family Family, permit func(netip.Addr) bool) {
	resolverProbe := DNS
	needsSocket := false
	switch row.Probe {
	case DNS, DNSUDP, DNSTCP, DoT, DoH, DoQ, DoH3:
		resolverProbe = row.Probe
	case TCP, TLS, HTTP, HTTPS:
		needsSocket = true
		if path.DialTCP == nil {
			row.Status, row.Reason = Unsupported, string(ErrNoProbeCapability)
			return
		}
	default:
		row.Status, row.Reason = Unsupported, string(ErrNoProbeCapability)
		return
	}
	var resolved Resolution
	if addr, err := netip.ParseAddr(target.Host); err == nil {
		if !needsSocket {
			row.Status, row.Reason = Unsupported, "dns_requires_hostname"
			return
		}
		resolved.Addresses = []netip.Addr{addr}
	} else {
		if path.Resolve == nil {
			row.Status, row.Reason = Unsupported, string(ErrResolverUnsupported)
			return
		}
		resolved, err = path.Resolve(ctx, target.Host, family, resolverProbe)
		if path.Evidence.Mode == HostBaseline && !outsidePanel(resolved.Socket) {
			row.Status, row.Reason = Unobservable, string(ErrBaselineUnobservable)
			return
		}
		if err != nil {
			row.Status = classify(err, ResolutionFailed)
			if errors.Is(err, ErrResolverUnsupported) || errors.Is(err, ErrNoProbeCapability) {
				row.Status, row.Reason = Unsupported, pathReason(err)
			} else if errors.Is(err, ErrBaselineUnobservable) || errors.Is(err, ErrGenerationChanged) {
				row.Status, row.Reason = Unobservable, pathReason(err)
			}
			return
		}
		if !operationref.ValidToken(resolved.Context, 64) {
			row.Status, row.Reason = Unobservable, "dns_context_not_observed"
			return
		}
		if resolverProbe != DNS && resolved.Transport != string(resolverProbe) {
			row.Status, row.Reason = Unobservable, "dns_transport_not_observed"
			return
		}
		row.DNSSocket = socketObservation(resolved.Socket)
		row.DNSContext = resolved.Context
		if operationref.ValidToken(resolved.Transport, 64) {
			row.DNSTransport = resolved.Transport
		}
		if resolved.RCode != nil && *resolved.RCode <= 4095 {
			value := *resolved.RCode
			row.DNSRCode = &value
		}
	}
	if len(resolved.Addresses) > maxDNSAddresses {
		row.Status, row.Reason = Rejected, "dns_address_budget_exceeded"
		return
	}
	addresses := make([]netip.Addr, 0, len(resolved.Addresses))
	for _, address := range resolved.Addresses {
		// Reject the whole mixed response, including addresses of other families.
		// The approved literal is consumed directly by the same path's dialer.
		if !basePublicAddress(address) || !permit(address.Unmap()) {
			row.Status, row.Reason = Rejected, "dns_or_literal_address_not_public"
			return
		}
		address = address.Unmap()
		if family == Any || family == IPv4 && address.Is4() || family == IPv6 && address.Is6() {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) != 0 {
		ordered := slices.Clone(addresses)
		slices.SortFunc(ordered, netip.Addr.Compare)
		ordered = slices.Compact(ordered)
		row.AnswerDigest, row.AnswerCount = revision(ordered), len(ordered)
	}
	if !needsSocket && (len(addresses) != 0 || row.DNSRCode != nil) {
		row.Status = DNSResponse
		return
	}
	if row.DNSRCode != nil && *row.DNSRCode != 0 {
		row.Status, row.Reason = ResolutionFailed, "dns_negative_response"
		return
	}
	if len(addresses) == 0 {
		row.Status, row.Reason = ResolutionFailed, "no_address_for_family"
		return
	}
	address := addresses[0]
	if address.Is4() {
		row.AddressFamily = IPv4
	} else {
		row.AddressFamily = IPv6
	}
	port := uint16(443)
	if row.Probe == HTTP {
		port = 80
	}
	conn, evidence, err := path.DialTCP(ctx, netip.AddrPortFrom(address, port))
	if conn != nil {
		defer conn.Close()
	}
	if path.Evidence.Mode == HostBaseline && !outsidePanel(evidence) {
		row.Status, row.Reason = Unobservable, string(ErrBaselineUnobservable)
		return
	}
	if err != nil || conn == nil {
		row.Status = classify(err, DialFailed)
		var unavailable PathError
		if errors.Is(err, ErrTargetRejected) {
			row.Status, row.Reason = Rejected, pathReason(err)
		} else if errors.As(err, &unavailable) {
			row.Status, row.Reason = Unobservable, pathReason(err)
		}
		return
	}
	row.Socket = socketObservation(evidence)
	if row.Probe == TCP {
		row.Status = OK
		return
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		row.Status, row.Reason = Unsupported, "transport_deadline_unavailable"
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	stream := conn
	if row.Probe == TLS || row.Probe == HTTPS {
		secure := tls.Client(stream, &tls.Config{ServerName: target.Host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		if err := secure.HandshakeContext(ctx); err != nil {
			row.Status = classify(err, TLSFailed)
			return
		}
		row.TLSVerified = true
		if row.Probe == TLS {
			row.Status = OK
			return
		}
		stream = secure
	}
	authority := target.Host
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	request := &http.Request{Method: http.MethodHead, URL: &url.URL{Path: "/"}, Host: authority, Header: http.Header{}, Close: true}
	if err := request.Write(stream); err != nil {
		row.Status = classify(err, ProtocolError)
		return
	}
	// Informational and final heads spend the same budget. Do not upgrade,
	// follow redirects, read a body, or copy peer-controlled headers.
	reader := bufio.NewReader(io.LimitReader(stream, maxHeaderBytes))
	for range 4 {
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			row.Status = classify(err, ProtocolError)
			return
		}
		switch {
		case response.StatusCode >= 200 && response.StatusCode <= 599:
			row.HTTPStatus, row.Status = response.StatusCode, HTTPResponse
			return
		case response.StatusCode < 100 || response.StatusCode == 101 || response.StatusCode >= 200:
			row.Status = ProtocolError
			return
		}
	}
	row.Status, row.Reason = ProtocolError, "http_informational_response_limit"
}

func outsidePanel(e SocketEvidence) bool {
	return e.OutsidePanel && operationref.ValidToken(e.Interface, 64)
}

func socketObservation(e SocketEvidence) *SocketEvidence {
	if !validText(e.Egress, 256, false) {
		e.Egress = ""
	}
	if !operationref.ValidToken(e.Interface, 64) {
		e.Interface, e.OutsidePanel = "", false
	}
	if e == (SocketEvidence{}) {
		return nil
	}
	return &e
}

func classify(err error, fallback Code) Code {
	switch {
	case errors.Is(err, context.Canceled):
		return Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return Timeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return Timeout
	}
	var verify *tls.CertificateVerificationError
	var hostname x509.HostnameError
	if errors.As(err, &verify) || errors.As(err, &hostname) {
		return CertificateInvalid
	}
	return fallback
}
