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
	MaxProbes   = 32
	RunBudget   = 30 * time.Second
	ProbeBudget = 5 * time.Second
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
	GroupID         string        `json:"groupId"`
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
	Interface    string `json:"interface,omitempty"`
	Egress       string `json:"egress,omitempty"`
	OutsidePanel bool   `json:"outsidePanel,omitempty"`
}

type Resolution struct {
	Addresses []netip.Addr
	Context   string
	Transport string
	RCode     *uint16
	Socket    SocketEvidence
}

type Path struct {
	Evidence PathEvidence
	Current  func(context.Context) error
	Resolve  func(context.Context, string, Family, Probe) (Resolution, error)
	DialTCP  func(context.Context, netip.AddrPort) (net.Conn, SocketEvidence, error)
}

// Provider must bind Core operations to the selected generation, and must
// never provide another path when the requested one is not available.
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
	TLSFailed          Code = "tls_failed"
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
	TargetRef     string           `json:"targetRef"`
	Status        Code             `json:"status"`
	Reason        string           `json:"reason,omitempty"`
	ElapsedMS     int64            `json:"elapsedMs"`
	AddressFamily Family           `json:"addressFamily,omitempty"`
	DNSContext    string           `json:"dnsContext,omitempty"`
	DNSTransport  string           `json:"dnsTransport,omitempty"`
	DNSRCode      *uint16          `json:"dnsRcode,omitempty"`
	DNSSocket     *SocketEvidence  `json:"dnsSocket,omitempty"`
	AnswerCount   int              `json:"answerCount,omitempty"`
	AnswerDigest  string           `json:"answerDigest,omitempty"`
	TLSVerified   bool             `json:"tlsVerified,omitempty"`
	HTTPStatus    int              `json:"httpStatus,omitempty"`
	Socket        *SocketEvidence  `json:"socket,omitempty"`
	Proof         *health.Evidence `json:"evidence,omitempty"`
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
}

func requestedCells(group Group, req RunRequest) ([]Cell, error) {
	if req.GroupID != group.ID || group.validate() != nil || !validID(group.ID) || req.Family != Any && req.Family != IPv4 && req.Family != IPv6 {
		return nil, ErrInvalidRun
	}
	selection := req.Path
	if !validText(selection.Ref, 256, selection.Mode != HostBaseline) || !validText(selection.Resolver, 256, false) {
		return nil, ErrInvalidRun
	}
	switch selection.Mode {
	case Panel, Outbound:
	case HostBaseline:
		if selection.Ref != "" {
			return nil, ErrInvalidRun
		}
	default:
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
	if len(cells) > MaxProbes {
		return nil, ErrInvalidRun
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

type activeRun struct {
	done   chan struct{}
	cancel context.CancelFunc
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
	if err != nil || provider == nil || permit == nil || ctx == nil {
		return Report{}, ErrInvalidRun
	}
	c.mu.Lock()
	if !c.active || host != c.host || ctx.Err() != nil {
		c.mu.Unlock()
		return Report{}, ErrInactive
	}
	if c.run != nil {
		c.mu.Unlock()
		return Report{}, ErrBusy
	}
	runCtx, cancel := context.WithTimeout(ctx, RunBudget)
	current := &activeRun{done: make(chan struct{}), cancel: cancel}
	c.run = current
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		c.run = nil
		close(current.done)
		c.mu.Unlock()
	}()

	ref := operationref.NewReference(ID, group.ID, newID("probe-"))
	deadline, _ := runCtx.Deadline()
	report := Report{Path: req.Path, Family: req.Family, GroupID: group.ID, GroupRevision: group.Revision(),
		StartedAt: time.Now().UTC(), Results: make([]Result, 0, len(cells))}
	path, pathErr := provider.Open(runCtx, host, req.Path)
	if pathErr == nil {
		if path.Current == nil || path.Evidence.Host != host || path.Evidence.Mode != req.Path.Mode || !validPathEvidence(path.Evidence) {
			pathErr = PathError("path_evidence_unavailable")
		} else {
			value := path.Evidence
			report.Evidence = &value
		}
	}
	for _, cell := range cells {
		target := group.Targets[cell.Target]
		row := Result{Cell: cell, TargetRef: health.Revision(target.Host)}
		started := time.Now()
		switch {
		case runCtx.Err() != nil:
			row.Status = classify(runCtx.Err(), Canceled)
		case pathErr != nil:
			row.Status, row.Reason = PathUnavailable, pathReason(pathErr)
		default:
			probeCtx, cancelProbe := context.WithTimeout(runCtx, ProbeBudget)
			if err := path.Current(probeCtx); err != nil {
				row.Status, row.Reason = Unobservable, pathReason(err)
			} else {
				performProbe(probeCtx, &row, target, path, req.Family, permit)
				if probeCtx.Err() == nil {
					if err := path.Current(probeCtx); err != nil {
						row = Result{Cell: cell, TargetRef: row.TargetRef, Status: Unobservable, Reason: pathReason(err)}
					}
				} else {
					row = Result{Cell: cell, TargetRef: row.TargetRef, Status: classify(probeCtx.Err(), Canceled)}
				}
			}
			cancelProbe()
		}
		row.ElapsedMS = time.Since(started).Milliseconds()
		if row.Status == OK || row.Status == HTTPResponse && row.HTTPStatus >= 200 && row.HTTPStatus < 300 ||
			row.Status == DNSResponse && row.AnswerCount > 0 && (row.DNSRCode == nil || *row.DNSRCode == 0) {
			observed := revision(struct {
				Run, Group string
				Path       PathEvidence
				Result     Result
			}{ref.OperationID, report.GroupRevision, path.Evidence, row})
			result := health.Result{ResourceID: group.ID, Status: health.StatusOK, Check: string(cell.Probe), FactCode: string(row.Status)}
			row.Proof = health.WithEvidence(result, ID, health.ProbeOK, "manual-blockcheck", observed, time.Now().UTC(), time.Minute).Evidence
		}
		report.Results = append(report.Results, row)
	}
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
	case OK, DNSResponse, HTTPResponse, ResolutionFailed, Timeout, Refused, DialFailed, TLSFailed, CertificateInvalid, ProtocolError:
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
	}
	return r
}
