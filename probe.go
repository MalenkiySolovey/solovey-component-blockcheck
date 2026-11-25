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
	"time"

	"github.com/MalenkiySolovey/solovey-host/operationref"
)

const maxHeaderBytes = 16 << 10
const maxDNSAddresses = 64
const maxTransferBytes = 64 << 10
const maxTransferFramingBytes = 32 << 10

func performProbe(ctx context.Context, row *Result, target Target, path Path, family Family, permit func(netip.Addr) bool) {
	resolverProbe := DNS
	needsSocket := false
	dial := path.DialTCP
	datagram := false
	switch row.Probe {
	case DNS, DNSUDP, DNSTCP, DoT, DoH, DoQ, DoH3:
		resolverProbe = row.Probe
	case TCP, TLS, TLS12, TLS13, HTTP, HTTPS, HTTPSChrome, HTTPData, HTTPSData:
		needsSocket = true
	case QUIC, HTTP3, STUN:
		needsSocket, datagram, dial = true, true, path.DialUDP
	default:
		row.Status, row.Reason = Unsupported, string(ErrNoProbeCapability)
		return
	}
	if needsSocket && dial == nil {
		row.Status, row.Reason = Unsupported, string(ErrNoProbeCapability)
		return
	}
	var resolved Resolution
	row.Stage = StageDNS
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
		row.DNSSocket = socketObservation(resolved.Socket)
		if operationref.ValidToken(resolved.Context, 64) {
			row.DNSContext = resolved.Context
		}
		if operationref.ValidToken(resolved.Transport, 64) {
			row.DNSTransport = resolved.Transport
		}
		if operationref.ValidToken(resolved.ConfiguredTransport, 64) {
			row.DNSConfiguredTransport = resolved.ConfiguredTransport
		}
		if resolved.RCode != nil && *resolved.RCode <= 4095 {
			value := *resolved.RCode
			row.DNSRCode = &value
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
		if row.DNSContext == "" {
			row.Status, row.Reason = Unobservable, "dns_context_not_observed"
			return
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
	if resolverProbe != DNS && row.DNSTransport != string(resolverProbe) {
		row.Status, row.Reason = Unobservable, "dns_transport_not_observed"
		return
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
	row.address = address
	row.AttemptedAddress = address.String()
	if address.Is4() {
		row.AddressFamily = IPv4
	} else {
		row.AddressFamily = IPv6
	}
	port := uint16(443)
	if row.Probe == HTTP || row.Probe == HTTPData {
		port = 80
	} else if row.Probe == STUN {
		port = target.Port
	}
	row.Stage = StageTCP
	if datagram {
		row.Stage = StageUDP
	}
	conn, evidence, err := dial(ctx, netip.AddrPortFrom(address, port))
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
	if row.Probe == STUN {
		probeSTUN(ctx, row, conn)
		return
	}
	if datagram {
		probeQUIC(ctx, row, conn, quicTLSConfig(target.Host))
		return
	}
	if row.Probe == TCP {
		switch {
		case evidence.ProxyTransportOnly:
			row.Status, row.Reason = Unobservable, "proxy_endpoint_tcp_not_observed"
		case evidence.ProxyAccepted:
			row.Status, row.Reason = Unobservable, "proxy_connect_not_endpoint_proof"
		default:
			row.Status = OK
		}
		return
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		row.Status, row.Reason = Unsupported, "transport_deadline_unavailable"
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if row.Probe == HTTPSChrome {
		probeChromeHTTPS(ctx, row, conn, target.Host, nil)
		return
	}
	stream := conn
	switch row.Probe {
	case TLS, TLS12, TLS13, HTTPS, HTTPSData:
		secure := handshake(ctx, row, stream, probeTLSConfig(row.Probe, target.Host))
		if secure == nil {
			return
		}
		if row.Probe == TLS || row.Probe == TLS12 || row.Probe == TLS13 {
			row.Status = OK
			return
		}
		stream = secure
	}
	probeHTTP(row, target.Host, stream)
}

func probeTLSConfig(probe Probe, host string) *tls.Config {
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	switch probe {
	case TLS12:
		config.MaxVersion = tls.VersionTLS12
	case TLS13:
		config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	}
	return config
}

func handshake(ctx context.Context, row *Result, stream net.Conn, config *tls.Config) *tls.Conn {
	row.Stage = StageTLS
	secure := tls.Client(stream, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		row.Status = classify(err, TLSFailed)
		if row.Status == CertificateInvalid {
			row.Stage = StageCertificate
		}
		return nil
	}
	state := secure.ConnectionState()
	row.TLSVerified, row.TLSVersion = len(state.VerifiedChains) != 0, tls.VersionName(state.Version)
	return secure
}

func probeHTTP(row *Result, host string, stream io.ReadWriter) {
	row.Stage = StageHTTP
	authority := host
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	request := &http.Request{Method: http.MethodHead, URL: &url.URL{Path: "/"}, Host: authority, Header: http.Header{}, Close: true}
	transfer := row.Probe == HTTPData || row.Probe == HTTPSData
	if transfer {
		request.Method = http.MethodGet
		request.Header.Set("Accept-Encoding", "identity")
	}
	if err := request.Write(stream); err != nil {
		row.Status = classify(err, ProtocolError)
		return
	}
	// All response heads share a budget. Never follow redirects or export headers.
	raw := &io.LimitedReader{R: stream, N: maxHeaderBytes}
	reader := bufio.NewReader(raw)
	for range 4 {
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			row.Status = classify(err, ProtocolError)
			if raw.N == 0 {
				row.Status, row.Reason = ProtocolError, "http_header_budget_exceeded"
			}
			return
		}
		switch {
		case response.StatusCode >= 200 && response.StatusCode <= 599:
			row.HTTPStatus, row.Status = response.StatusCode, HTTPResponse
			if row.Probe == HTTPSChrome {
				if response.ProtoMajor != 1 || response.ProtoMinor > 1 {
					row.HTTPStatus, row.Status = 0, ProtocolError
					return
				}
				row.HTTPProtocol = response.Proto
			}
			if transfer && response.StatusCode < 300 {
				if response.Body == http.NoBody {
					row.Reason = "http_no_transfer_body"
				} else {
					readTransfer(row, response, raw)
				}
			}
			return
		case response.StatusCode < 100 || response.StatusCode == 101 || response.StatusCode >= 200:
			row.Status = ProtocolError
			return
		}
	}
	row.Status, row.Reason = ProtocolError, "http_informational_response_limit"
}

func readTransfer(row *Result, response *http.Response, raw *io.LimitedReader) {
	row.Stage = StageTransfer
	if response.ContentLength > 0 {
		row.BodyExpected = response.ContentLength
	}
	// Bound peer-controlled framing too (e.g. chunk extensions).
	raw.N = maxTransferBytes + maxTransferFramingBytes
	started := time.Now()
	n, err := io.CopyN(io.Discard, response.Body, maxTransferBytes)
	row.BodyBytes, row.BodyReadMS = n, time.Since(started).Milliseconds()
	switch {
	case err == nil:
		if row.BodyExpected != n {
			row.Reason = "transfer_sample_limit"
		}
	case raw.N == 0:
		row.Status, row.Reason = Unsupported, "http_transfer_budget_exceeded"
	case errors.Is(err, io.EOF):
		// EOF is normal if HTTP framing did not promise further data.
		if response.ContentLength > n {
			row.Status = StreamClosed
		} else if n == 0 {
			row.Reason = "http_no_transfer_body"
		}
	default:
		row.Status = classify(err, ProtocolError)
	}
	// The caller closes the connection; closing Body here can drain the rest.
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
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return ConnectionReset
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return StreamClosed
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
