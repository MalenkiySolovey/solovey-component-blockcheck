package blockcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	hostports "github.com/MalenkiySolovey/solovey-host/componenthost"
	"github.com/MalenkiySolovey/solovey-host/componenthost/health"
	"github.com/MalenkiySolovey/solovey-host/hostref"
	"github.com/MalenkiySolovey/solovey-host/operationref"
)

const (
	// The compatibility JSON endpoint has a fixed response time; the streamed
	// runner batches the complete selected catalog instead.
	maxSynchronousProbes = 32
	RunBudget            = 30 * time.Second
	ProbeBudget          = 5 * time.Second
)

type Mode string

const (
	Panel        Mode = "PANEL"
	HostBaseline Mode = "HOST_BASELINE"
	Outbound     Mode = "OUTBOUND"
)

type Family string

const (
	Any  Family = "any"
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

type PathSelection struct {
	Mode     Mode   `json:"mode"`
	Ref      string `json:"ref,omitempty"`
	Resolver string `json:"resolver,omitempty"`
}

type Cell struct {
	Target int   `json:"target"`
	Probe  Probe `json:"probe"`
}

type RunRequest struct {
	GroupID         string        `json:"groupId,omitempty"`
	CatalogRevision string        `json:"catalogRevision"`
	Path            PathSelection `json:"path"`
	Family          Family        `json:"family"`
	Cells           []Cell        `json:"cells,omitempty"`
}

// PathEvidence describes a path actually offered by its semantic owner. A
// selected proxy member, DNS transport or interface is not inferred here.
type PathEvidence struct {
	Host       hostref.Ref `json:"host"`
	Mode       Mode        `json:"mode"`
	Generation string      `json:"generation,omitempty"`
	Scope      string      `json:"scope"`
	Context    string      `json:"context,omitempty"`
}

type SocketEvidence struct {
	Interface     string `json:"interface,omitempty"`
	Egress        string `json:"egress,omitempty"`
	OutsidePanel  bool   `json:"outsidePanel,omitempty"`
	ProxyAccepted bool   `json:"proxyAccepted,omitempty"`
	// A lazy proxy stream can be returned before an endpoint request is sent.
	ProxyTransportOnly bool `json:"proxyTransportOnly,omitempty"`
	// Egress records the native route decision, not a socket observation.
	RouteSelectionOnly bool `json:"routeSelectionOnly,omitempty"`
}

type Resolution struct {
	Addresses           []netip.Addr
	Context             string
	Transport           string
	ConfiguredTransport string
	RCode               *uint16
	Socket              SocketEvidence
}

type Path struct {
	Evidence PathEvidence
	Current  func(context.Context) error
	Resolve  func(context.Context, string, Family, Probe) (Resolution, error)
	DialTCP  func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error)
	// A routed stream may need client bytes before routing and egress are
	// observable. The observer does not turn tunnel setup into a TCP result.
	DialNamedStream func(context.Context, string, netip.AddrPort) (net.Conn, func() (SocketEvidence, error), error)
	// DialUDP returns a connected datagram transport to the admitted destination.
	DialUDP func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error)
}

// Provider must bind Core operations to the selected generation, honor probe
// contexts, and allow concurrent calls to the opened path. It must never
// provide another path when the requested one is not available.
type Provider interface {
	Open(context.Context, hostref.Ref, PathSelection) (Path, error)
}

type ProviderFunc func(context.Context, hostref.Ref, PathSelection) (Path, error)

func (f ProviderFunc) Open(ctx context.Context, host hostref.Ref, selection PathSelection) (Path, error) {
	return f(ctx, host, selection)
}

type Code string

const (
	OK                 Code = "ok"
	ResolutionFailed   Code = "resolution_failed"
	DNSResponse        Code = "dns_response"
	Timeout            Code = "timeout"
	Canceled           Code = "canceled"
	Refused            Code = "connection_refused"
	DialFailed         Code = "connection_failed"
	ConnectionReset    Code = "connection_reset"
	StreamClosed       Code = "stream_closed"
	TLSFailed          Code = "tls_failed"
	QUICFailed         Code = "quic_failed"
	CertificateInvalid Code = "certificate_invalid"
	ProtocolError      Code = "protocol_error"
	HTTPResponse       Code = "http_response"
	Unsupported        Code = "unsupported"
	Unobservable       Code = "unobservable"
	Rejected           Code = "target_rejected"
	PathUnavailable    Code = "path_unavailable"
)

type PathError string

func (e PathError) Error() string { return string(e) }

const (
	ErrPanelIngressUnqualified PathError = "panel_ingress_not_qualified"
	ErrPanelRouteUnobserved    PathError = "panel_dispatch_not_observed"
	ErrBaselineUnobservable    PathError = "host_baseline_not_observable"
	ErrOutboundUnavailable     PathError = "outbound_not_available"
	ErrGenerationChanged       PathError = "core_generation_changed"
	ErrResolverUnsupported     PathError = "dns_transport_not_available"
	ErrNoProbeCapability       PathError = "probe_not_available_on_path"
	ErrTargetRejected          PathError = "target_policy_rejected"
)

var (
	ErrInactive   = errors.New("blockcheck_inactive")
	ErrBusy       = errors.New("blockcheck_busy")
	ErrInvalidRun = errors.New("blockcheck_invalid_run")
)

type Result struct {
	Cell
	TargetRef              string           `json:"targetRef"`
	Status                 Code             `json:"status"`
	Stage                  Stage            `json:"stage,omitempty"`
	Interpretation         *Finding         `json:"interpretation,omitempty"`
	Reason                 string           `json:"reason,omitempty"`
	ElapsedMS              int64            `json:"elapsedMs"`
	AddressFamily          Family           `json:"addressFamily,omitempty"`
	AttemptedAddress       string           `json:"attemptedAddress,omitempty"`
	address                netip.Addr       // binary pairing key for TLS observations
	DNSContext             string           `json:"dnsContext,omitempty"`
	DNSTransport           string           `json:"dnsTransport,omitempty"`
	DNSConfiguredTransport string           `json:"dnsConfiguredTransport,omitempty"`
	DNSRCode               *uint16          `json:"dnsRcode,omitempty"`
	DNSSocket              *SocketEvidence  `json:"dnsSocket,omitempty"`
	AnswerCount            int              `json:"answerCount,omitempty"`
	AnswerDigest           string           `json:"answerDigest,omitempty"`
	TLSVerified            bool             `json:"tlsVerified,omitempty"`
	TLSVersion             string           `json:"tlsVersion,omitempty"`
	TLSProfile             string           `json:"tlsProfile,omitempty"`
	HTTPStatus             int              `json:"httpStatus,omitempty"`
	HTTPProtocol           string           `json:"httpProtocol,omitempty"`
	HTTPResponseStartMS    *int64           `json:"httpResponseStartMs,omitempty"`
	BodyBytes              int64            `json:"bodyBytes,omitempty"`
	BodyReadMS             *int64           `json:"bodyReadMs,omitempty"`
	BodyMaxGapMS           *int64           `json:"bodyMaxGapMs,omitempty"`
	BodyExpected           int64            `json:"bodyExpected,omitempty"`
	Socket                 *SocketEvidence  `json:"socket,omitempty"`
	Proof                  *health.Evidence `json:"evidence,omitempty"`
}

type Report struct {
	Job           operationref.Job `json:"job"`
	Path          PathSelection    `json:"path"`
	Evidence      *PathEvidence    `json:"pathEvidence,omitempty"`
	GroupID       string           `json:"groupId"`
	GroupRevision string           `json:"groupRevision"`
	Family        Family           `json:"family"`
	StartedAt     time.Time        `json:"startedAt"`
	FinishedAt    time.Time        `json:"finishedAt"`
	Results       []Result         `json:"results"`
	Findings      []GroupFinding   `json:"findings,omitempty"`
}

func requestedCells(group Group, req RunRequest) ([]Cell, error) {
	if req.GroupID != group.ID || group.validate() != nil || !validID(group.ID) || !validRunPath(req.Path, req.Family) {
		return nil, ErrInvalidRun
	}
	cells := slices.Clone(req.Cells)
	if len(cells) == 0 {
		for i, target := range group.Targets {
			for _, probe := range target.Probes {
				cells = append(cells, Cell{Target: i, Probe: probe})
			}
		}
	}
	seen := map[Cell]bool{}
	for _, cell := range cells {
		if seen[cell] || cell.Target < 0 || cell.Target >= len(group.Targets) || !slices.Contains(group.Targets[cell.Target].Probes, cell.Probe) {
			return nil, ErrInvalidRun
		}
		seen[cell] = true
	}
	return cells, nil
}

func validRunPath(selection PathSelection, family Family) bool {
	if family != Any && family != IPv4 && family != IPv6 || !validText(selection.Resolver, 256, false) {
		return false
	}
	switch selection.Mode {
	case Panel, Outbound:
		return validText(selection.Ref, 256, true)
	case HostBaseline:
		return selection.Ref == ""
	default:
		return false
	}
}

type activeRun struct {
	done      chan struct{}
	cancel    context.CancelFunc
	operation string // Only a streamed run exposes explicit cancellation.
}

// Component owns only cooperative admission to one operator-requested run.
// No goroutine, listener or timer exists while the component is idle.
type Component struct {
	mu     sync.Mutex
	host   hostref.Ref
	active bool
	run    *activeRun
}

func (c *Component) Start(_ context.Context, ports hostports.Ports) error {
	if !ports.Host.IsLocal() {
		return ErrInactive
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run != nil && (!c.active || c.host != ports.Host) {
		return ErrBusy
	}
	c.host, c.active = ports.Host, true
	return nil
}

func (c *Component) Stop(ctx context.Context) error {
	c.mu.Lock()
	c.active = false
	running := c.run
	if running != nil {
		running.cancel()
	}
	c.mu.Unlock()
	if running != nil {
		select {
		case <-running.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *Component) DropData(ctx context.Context, ports hostports.Ports) error {
	if ports.DropOwnedSettings == nil || !ports.Host.IsLocal() {
		return ErrInactive
	}
	return ports.DropOwnedSettings(ctx)
}

// Run requires a host-owned provider and public-destination policy. It does
// not supply a resolver or dialer of its own, including on capability failure.
func (c *Component) Run(ctx context.Context, host hostref.Ref, catalog Catalog, req RunRequest, provider Provider, permit func(netip.Addr) bool) (Report, error) {
	if req.CatalogRevision != catalog.Revision() {
		return Report{}, ErrStaleCatalog
	}
	group, ok := catalog.Group(req.GroupID)
	if !ok {
		return Report{}, ErrGroupNotFound
	}
	cells, err := requestedCells(group, req)
	if err != nil || len(cells) > maxSynchronousProbes || provider == nil || permit == nil || ctx == nil {
		return Report{}, ErrInvalidRun
	}
	runCtx, cancel := context.WithTimeout(ctx, RunBudget)
	defer cancel()
	release, err := c.admit(runCtx, host, cancel, "")
	if err != nil {
		return Report{}, err
	}
	defer release()

	ref := operationref.NewReference(ID, group.ID, newID("probe-"))
	deadline, _ := runCtx.Deadline()
	report := Report{Path: req.Path, Family: req.Family, GroupID: group.ID, GroupRevision: group.Revision(),
		StartedAt: time.Now().UTC(), Results: make([]Result, 0, len(cells))}
	path, pathErr := openPath(runCtx, host, req.Path, provider)
	if pathErr == nil {
		report.Evidence = &path.Evidence
	}
	for _, cell := range cells {
		row := probeCell(runCtx, cell, group.Targets[cell.Target], path, pathErr, req.Family, permit)
		attachProof(&row, ref, report.GroupRevision, path.Evidence)
		report.Results = append(report.Results, row)
	}
	var pairs tlsPairs
	report.Findings = pairs.observe(report.Results)
	phase, outcome := "COMPLETED", operationref.OutcomeCommitted
	if runCtx.Err() != nil {
		phase, outcome = strings.ToUpper(string(classify(runCtx.Err(), Canceled))), operationref.OutcomeFailed
	} else if pathErr != nil {
		phase, outcome = "PATH_UNAVAILABLE", operationref.OutcomeFailed
	}
	report.FinishedAt = time.Now().UTC()
	report.Job = operationref.ProjectJob(operationref.Change{Reference: ref, Revision: 1, OwnerPhase: phase,
		ExpectedRevision: report.GroupRevision, Outcome: outcome}, nil, false)
	report.Job.Deadline = deadline.Unix()
	return report, nil
}

func (c *Component) admit(ctx context.Context, host hostref.Ref, cancel context.CancelFunc, operation string) (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || host != c.host || ctx.Err() != nil {
		return nil, ErrInactive
	}
	if c.run != nil {
		return nil, ErrBusy
	}
	current := &activeRun{done: make(chan struct{}), cancel: cancel, operation: operation}
	c.run = current
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.run = nil
		close(current.done)
	}, nil
}

func openPath(ctx context.Context, host hostref.Ref, selection PathSelection, provider Provider) (Path, error) {
	path, err := provider.Open(ctx, host, selection)
	if err != nil {
		return Path{}, err
	}
	if path.Current == nil || path.Evidence.Host != host || path.Evidence.Mode != selection.Mode || !validPathEvidence(path.Evidence) {
		return Path{}, PathError("path_evidence_unavailable")
	}
	return path, nil
}

func probeCell(ctx context.Context, cell Cell, target Target, path Path, pathErr error, family Family, permit func(netip.Addr) bool) Result {
	row := Result{Cell: cell, TargetRef: health.Revision(target.Host)}
	started := time.Now()
	switch {
	case ctx.Err() != nil:
		row.Status = classify(ctx.Err(), Canceled)
	case pathErr != nil:
		row.Status, row.Reason = PathUnavailable, pathReason(pathErr)
	default:
		probeCtx, cancel := context.WithTimeout(ctx, ProbeBudget)
		defer cancel()
		if err := path.Current(probeCtx); err != nil {
			row.Status, row.Reason = Unobservable, pathReason(err)
		} else {
			performProbe(probeCtx, &row, target, path, family, permit)
			if err := ctx.Err(); err != nil {
				row = Result{Cell: cell, TargetRef: row.TargetRef, Status: classify(err, Canceled)}
			} else if probeCtx.Err() != nil {
				// The probe expired. Keep partial evidence only while the path is current.
				if err := checkCurrent(ctx, path); err != nil {
					row = Result{Cell: cell, TargetRef: row.TargetRef, Status: Unobservable, Reason: pathReason(err)}
				} else {
					row.Status, row.Reason = Timeout, ""
				}
			} else if err := path.Current(probeCtx); err != nil {
				row = Result{Cell: cell, TargetRef: row.TargetRef, Status: Unobservable, Reason: pathReason(err)}
			}
		}
	}
	row.ElapsedMS = time.Since(started).Milliseconds()
	row.Interpretation = interpretProbe(row)
	return row
}

func attachProof(row *Result, ref operationref.Reference, groupRevision string, path PathEvidence) {
	if !row.positive() {
		return
	}
	observed := revision(struct {
		Run, Group string
		Path       PathEvidence
		Result     Result
	}{ref.OperationID, groupRevision, path, *row})
	result := health.Result{ResourceID: ref.ResourceID, Status: health.StatusOK, Check: string(row.Probe), FactCode: string(row.Status)}
	row.Proof = health.WithEvidence(result, ID, health.ProbeOK, "manual-blockcheck", observed, time.Now().UTC(), time.Minute).Evidence
}

func (r Result) positive() bool {
	if r.Probe == HTTPData || r.Probe == HTTPSData {
		return r.Status == HTTPResponse && r.HTTPStatus >= 200 && r.HTTPStatus < 300 && r.BodyBytes > 0
	}
	return r.Status == OK || r.Status == HTTPResponse && r.HTTPStatus >= 200 && r.HTTPStatus < 300 ||
		r.Status == DNSResponse && r.AnswerCount > 0 && (r.DNSRCode == nil || *r.DNSRCode == 0)
}

func validPathEvidence(e PathEvidence) bool {
	if !validText(e.Context, 256, true) || !operationref.ValidToken(e.Scope, 64) {
		return false
	}
	if e.Mode == HostBaseline {
		return e.Generation == ""
	}
	return operationref.ValidToken(e.Generation, 96)
}

func pathReason(err error) string {
	var reason PathError
	if errors.As(err, &reason) && operationref.ValidToken(string(reason), 64) {
		return string(reason)
	}
	if status := classify(err, PathUnavailable); status != PathUnavailable {
		return string(status)
	}
	return string(PathUnavailable)
}

func Comparable(a, b Report) bool {
	if a.Evidence == nil || b.Evidence == nil || a.Evidence.Host != b.Evidence.Host || a.GroupID != b.GroupID ||
		a.GroupRevision != b.GroupRevision || a.Family != b.Family || len(a.Results) == 0 || len(a.Results) != len(b.Results) ||
		a.StartedAt.Sub(b.StartedAt).Abs() > 15*time.Minute {
		return false
	}
	return slices.EqualFunc(a.Results, b.Results, func(a, b Result) bool {
		return a.Cell == b.Cell && a.TargetRef == b.TargetRef && comparableStatus(a.Status) && comparableStatus(b.Status)
	})
}

func comparableStatus(status Code) bool {
	switch status {
	case OK, DNSResponse, HTTPResponse, ResolutionFailed, Timeout, Refused, DialFailed, ConnectionReset, StreamClosed, TLSFailed, CertificateInvalid, ProtocolError:
		return true
	default:
		return false
	}
}

func (r Report) Redacted() Report {
	r.Path.Ref, r.Path.Resolver = "", ""
	if r.Evidence != nil {
		evidence := *r.Evidence
		evidence.Context = ""
		r.Evidence = &evidence
	}
	r.Results = slices.Clone(r.Results)
	for i := range r.Results {
		r.Results[i].Socket = nil
		r.Results[i].DNSSocket = nil
		r.Results[i].AttemptedAddress = ""
	}
	return r
}
