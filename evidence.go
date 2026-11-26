package blockcheck

type Depth string

const (
	Quick Depth = "quick"
	Deep  Depth = "deep"
)

func (d Depth) valid() bool { return d == "" || d == Quick || d == Deep }

// Deep adds applicable on-wire probes to the selected cells, not to the
// saved catalog. Neither mode changes the admitted destination or path.
func deepCells(cells []Cell) []Cell {
	seen := make(map[Cell]bool, len(cells))
	for _, cell := range cells {
		seen[cell] = true
	}
	var expanded []Cell
	for _, cell := range cells {
		expanded = append(expanded, cell)
		var extra []Probe
		switch cell.Probe {
		case TLS:
			extra = []Probe{TLS12, TLS13}
		case HTTPS:
			extra = []Probe{TLS12, TLS13, HTTPSChrome, HTTPSData}
		case HTTPSChrome:
			extra = []Probe{TLS13}
		case HTTP:
			extra = []Probe{HTTPData}
		}
		for _, probe := range extra {
			additional := Cell{Target: cell.Target, Probe: probe}
			if !seen[additional] {
				seen[additional] = true
				expanded = append(expanded, additional)
			}
		}
	}
	return expanded
}

type Stage string

const (
	StageDNS         Stage = "dns"
	StageRoute       Stage = "route"
	StageTCP         Stage = "tcp"
	StageUDP         Stage = "udp"
	StageSTUN        Stage = "stun"
	StageQUIC        Stage = "quic"
	StageTLS         Stage = "tls"
	StageCertificate Stage = "certificate"
	StageHTTP        Stage = "http"
	StageTransfer    Stage = "transfer"
)

// Confidence describes the observation or contrast, not confidence that a
// particular operator, network device, or filtering mechanism caused it.
type Finding struct {
	Code         string   `json:"code"`
	Confidence   string   `json:"confidence"`
	Alternatives []string `json:"alternatives,omitempty"`
}

type GroupFinding struct {
	Target int     `json:"target"`
	Probes []Probe `json:"probes"`
	Finding
}

func fact(code string, alternatives ...string) *Finding {
	return &Finding{Code: code, Confidence: "observed", Alternatives: alternatives}
}

func interpretProbe(row Result) *Finding {
	switch row.Status {
	case Rejected, Unobservable, Unsupported, PathUnavailable, Canceled:
		return nil
	case CertificateInvalid:
		return fact("certificate_unverified", "certificate_configuration", "intermediary")
	}
	switch row.Stage {
	case StageDNS:
		if row.DNSRCode != nil && *row.DNSRCode != 0 {
			return fact("dns_negative", "resolver_policy", "dns_configuration")
		}
		if row.Status != DNSResponse || row.AnswerCount == 0 {
			return fact("dns_no_address", "resolver_policy", "dns_configuration", "path_or_service")
		}
	case StageTCP:
		if row.Status != OK {
			if row.Status == Refused {
				return fact("tcp_refused", "listener_or_firewall", "intermediary")
			}
			return fact("tcp_not_established", "path_or_service", "listener_or_firewall", "intermediary")
		}
	case StageUDP:
		return fact("udp_socket_unavailable", "listener_or_firewall", "path_or_service")
	case StageSTUN:
		if row.Status != OK {
			return fact("stun_binding_incomplete", "stun_support_policy", "path_or_service", "intermediary")
		}
	case StageQUIC:
		if row.Status != OK {
			return fact("quic_handshake_incomplete", "quic_support_policy", "path_or_service", "intermediary")
		}
	case StageTLS:
		if row.Status != OK {
			return fact("tls_handshake_incomplete", "tls_compatibility", "path_or_service", "intermediary")
		}
	case StageHTTP:
		if row.Status != HTTPResponse {
			return fact("http_response_incomplete", "service_or_proxy", "path_or_service")
		}
		if row.HTTPStatus >= 400 {
			return fact("http_error_response", "service_or_proxy", "service_request_policy")
		}
	case StageTransfer:
		if row.Status == StreamClosed || row.Status == ConnectionReset || row.Status == Timeout {
			return fact("transfer_interrupted", "service_or_proxy", "path_or_service")
		}
		if row.Status != HTTPResponse {
			return fact("transfer_protocol_error", "service_or_proxy", "path_or_service")
		}
		// The frozen reference uses 2.5 s as a threshold for investigating
		// pauses. Here the evidence is one in-body interval, not repeated
		// delays before responses or a diagnosis of filtering.
		if row.BodyMaxGapMS != nil && *row.BodyMaxGapMS >= 2500 {
			return fact("transfer_pause_observed", "service_or_proxy", "path_or_service", "client_scheduling")
		}
	}
	return nil
}

type tlsPairs struct {
	versions map[int]Result
	clients  map[int]Result
}

// TLS contrasts are evidence only on the same admitted address and path.
// It does not classify certificate failure or an isolated transport timeout
// as filtering. One contrast may reflect server policy or a transient fault.
func (p *tlsPairs) observe(rows []Result) []GroupFinding {
	var findings []GroupFinding
	for _, row := range rows {
		if !row.address.IsValid() || (!row.TLSVerified && row.Stage != StageTLS) {
			continue
		}
		if row.Probe == TLS12 || row.Probe == TLS13 {
			if other, ok := takeTLSPair(&p.versions, row); ok && (contrastedTLS(row, other) || contrastedTLS(other, row)) {
				findings = append(findings, tlsContrast(row.Target, TLS12, TLS13, "tls_version_difference"))
			}
		}
		if row.Probe == TLS13 || row.Probe == HTTPSChrome && row.TLSProfile == chromeTLSProfile {
			if other, ok := takeTLSPair(&p.clients, row); ok && (contrastedTLSClient(row, other) || contrastedTLSClient(other, row)) {
				findings = append(findings, tlsContrast(row.Target, TLS13, HTTPSChrome, "tls_client_profile_difference"))
			}
		}
	}
	return findings
}

func takeTLSPair(pending *map[int]Result, row Result) (Result, bool) {
	if *pending == nil {
		*pending = make(map[int]Result)
	}
	other, ok := (*pending)[row.Target]
	if !ok {
		(*pending)[row.Target] = row
		return Result{}, false
	}
	delete(*pending, row.Target)
	return other, row.Probe != other.Probe && row.address == other.address && row.TargetRef == other.TargetRef &&
		row.DNSContext == other.DNSContext && matchingSocketObservation(row.Socket, other.Socket)
}

func tlsContrast(target int, a, b Probe, code string) GroupFinding {
	return GroupFinding{Target: target, Probes: []Probe{a, b}, Finding: Finding{
		Code: code, Confidence: "indicative", Alternatives: []string{"tls_compatibility", "intermediary", "transient_failure"},
	}}
}

func matchingSocketObservation(a, b *SocketEvidence) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func contrastedTLS(passed, failed Result) bool {
	return passed.Status == OK && passed.TLSVerified && incompleteTLS(failed)
}

func contrastedTLSClient(passed, failed Result) bool {
	return passed.TLSVerified && passed.TLSVersion == "TLS 1.3" && incompleteTLS(failed)
}

func incompleteTLS(row Result) bool {
	return row.Stage == StageTLS && (row.Status == TLSFailed || row.Status == ConnectionReset || row.Status == StreamClosed || row.Status == Timeout)
}
