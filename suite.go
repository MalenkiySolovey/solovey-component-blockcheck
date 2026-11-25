package blockcheck

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/MalenkiySolovey/solovey-host/hostref"
	"github.com/MalenkiySolovey/solovey-host/operationref"
)

// A foreground run holds at most this many active probes. The number of
// batches depends on the selected definitions, not on the concurrency limit.
const probeBatchSize = 3

// Explicit selections encode target indexes separately from catalog entries.
// This is a request-size safeguard, not a limit on selected cells.
const MaxSuiteRequestBytes = 5*MaxCatalogBytes + 2048

var (
	ErrNoEnabledGroups = errors.New("blockcheck_no_enabled_groups")
	ErrRunNotFound     = errors.New("blockcheck_run_not_found")
)

type SuiteRequest struct {
	RunRequest
	All   bool  `json:"all,omitempty"`
	Depth Depth `json:"depth,omitempty"`
}

type SuiteProgress struct {
	GroupsDone  int `json:"groupsDone"`
	TotalGroups int `json:"totalGroups"`
	ProbesDone  int `json:"probesDone"`
	TotalProbes int `json:"totalProbes"`
}

type GroupProgress struct {
	ID        string `json:"id"`
	Completed int    `json:"completed"`
	Total     int    `json:"total"`
}

type SuiteEvent struct {
	Kind         string           `json:"kind"`
	Job          operationref.Job `json:"job"`
	Progress     SuiteProgress    `json:"progress"`
	Group        *GroupProgress   `json:"group,omitempty"`
	Rows         []Result         `json:"rows,omitempty"`
	Findings     []GroupFinding   `json:"findings,omitempty"`
	StartedAt    *time.Time       `json:"startedAt,omitempty"`
	FinishedAt   *time.Time       `json:"finishedAt,omitempty"`
	HistorySaved *bool            `json:"historySaved,omitempty"`
	// Group report metadata. Probe results arrive once, in their batch events.
	Report *Report `json:"report,omitempty"`
}

type plannedGroup struct {
	group Group
	cells []Cell
}

func prepareSuite(catalog Catalog, req SuiteRequest) ([]plannedGroup, SuiteProgress, time.Duration, error) {
	var progress SuiteProgress
	if err := catalog.Validate(); err != nil {
		return nil, progress, 0, err
	}
	if req.CatalogRevision != catalog.Revision() {
		return nil, progress, 0, ErrStaleCatalog
	}
	if !validRunPath(req.Path, req.Family) || !req.Depth.valid() || req.All && (req.GroupID != "" || len(req.Cells) != 0) || !req.All && req.GroupID == "" {
		return nil, progress, 0, ErrInvalidRun
	}
	groups := catalog.Groups
	if !req.All {
		group, ok := catalog.Group(req.GroupID)
		if !ok {
			return nil, progress, 0, ErrGroupNotFound
		}
		groups = []Group{group}
	}
	var plan []plannedGroup
	for _, group := range groups {
		if req.All && group.Disabled {
			continue
		}
		groupReq := req.RunRequest
		groupReq.GroupID = group.ID
		cells, err := requestedCells(group, groupReq)
		if err != nil {
			return nil, progress, 0, err
		}
		if req.Depth == Deep {
			cells = deepCells(cells)
		}
		group.Targets = slices.Clone(group.Targets)
		for i := range group.Targets {
			group.Targets[i].Probes = slices.Clone(group.Targets[i].Probes)
		}
		if group.Origin != nil {
			origin := *group.Origin
			group.Origin = &origin
		}
		plan = append(plan, plannedGroup{group, cells})
		progress.TotalProbes += len(cells)
	}
	progress.TotalGroups = len(plan)
	if len(plan) == 0 {
		return nil, progress, 0, ErrNoEnabledGroups
	}
	// The admission/response allowance scales with the number of batches,
	// leaving timing headroom without raising each individual probe's budget.
	batches := 1
	for _, group := range plan {
		batches += (len(group.cells) + probeBatchSize - 1) / probeBatchSize
	}
	return plan, progress, time.Duration(batches) * 2 * ProbeBudget, nil
}

// CancelSuite cancels only the matching foreground operation. It leaves the
// stream open so the caller can retain completed work and the terminal job.
func (c *Component) CancelSuite(host hostref.Ref, operation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host != c.host || c.run == nil || operation == "" || operation != c.run.operation {
		return ErrRunNotFound
	}
	c.run.cancel()
	return nil
}

// RunSuite is synchronous from the owner's perspective. The request supplies
// the entire lifetime and receives bounded events; there is no queue or retained
// server-side history. The provider is opened once, even on group/probe failure.
func (c *Component) RunSuite(ctx context.Context, host hostref.Ref, catalog Catalog, req SuiteRequest, provider Provider, permit func(netip.Addr) bool, emit func(SuiteEvent) error) error {
	if ctx == nil || provider == nil || permit == nil || emit == nil {
		return ErrInvalidRun
	}
	plan, progress, budget, err := prepareSuite(catalog, req)
	if err != nil {
		return err
	}
	resource := req.GroupID
	if req.All {
		resource = "catalog"
	}
	ref := operationref.NewReference(ID, resource, newID("suite-"))
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	release, err := c.admit(runCtx, host, cancel, ref.OperationID)
	if err != nil {
		return err
	}
	defer release()
	deadline, _ := runCtx.Deadline()
	var sequence uint64
	publish := func(event SuiteEvent, phase string, outcome operationref.Outcome, reason string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		sequence++
		event.Progress = progress
		event.Job = projectedJob(ref, sequence, req.CatalogRevision, deadline, phase, outcome, reason)
		if event.Group != nil {
			group := *event.Group
			event.Group = &group
		}
		return emit(event)
	}
	pending := operationref.OutcomePending
	started := time.Now().UTC()
	if err := publish(SuiteEvent{Kind: "started", StartedAt: &started}, "RUNNING", pending, ""); err != nil {
		return err
	}
	var path Path
	pathErr := runCtx.Err()
	if pathErr == nil {
		openCtx, stopOpen := context.WithTimeout(runCtx, ProbeBudget)
		path, pathErr = openPath(openCtx, host, req.Path, provider)
		stopOpen()
	}
	if pathErr == nil {
		for _, entry := range plan {
			if err := runCtx.Err(); err != nil {
				break
			}
			group := GroupProgress{ID: entry.group.ID, Total: len(entry.cells)}
			groupRef := operationref.NewReference(ID, entry.group.ID, newID("probe-"))
			var pairs tlsPairs
			report := Report{Path: req.Path, Family: req.Family, GroupID: entry.group.ID, GroupRevision: entry.group.Revision(),
				Evidence: &path.Evidence, StartedAt: time.Now().UTC()}
			if err := publish(SuiteEvent{Kind: "progress", Group: &group}, "RUNNING", pending, ""); err != nil {
				return err
			}
			for batch := range slices.Chunk(entry.cells, probeBatchSize) {
				if pathErr = checkCurrent(runCtx, path); pathErr != nil {
					break
				}
				rows := make([]Result, len(batch))
				var probes sync.WaitGroup
				for i, cell := range batch {
					probes.Go(func() {
						rows[i] = probeCell(runCtx, cell, entry.group.Targets[cell.Target], path, nil, req.Family, permit)
					})
				}
				probes.Wait()
				if pathErr = checkCurrent(runCtx, path); pathErr != nil {
					break
				}
				for i := range rows {
					if rows[i].Reason == string(ErrGenerationChanged) {
						pathErr = ErrGenerationChanged
						break
					}
					attachProof(&rows[i], groupRef, report.GroupRevision, path.Evidence)
				}
				if pathErr != nil {
					break
				}
				group.Completed += len(rows)
				progress.ProbesDone += len(rows)
				if err := publish(SuiteEvent{Kind: "progress", Group: &group, Rows: rows, Findings: pairs.observe(rows)}, "RUNNING", pending, ""); err != nil {
					return err
				}
			}
			phase, outcome, reason := "COMPLETED", operationref.OutcomeCommitted, ""
			if group.Completed != group.Total {
				phase, outcome, reason = suiteOutcome(runCtx, pathErr)
			}
			if outcome == operationref.OutcomeCommitted {
				progress.GroupsDone++
			}
			report.FinishedAt = time.Now().UTC()
			report.Job = projectedJob(groupRef, 1, report.GroupRevision, deadline, phase, outcome, reason)
			if err := publish(SuiteEvent{Kind: "group", Group: &group, Report: &report}, "RUNNING", pending, ""); err != nil {
				return err
			}
			if outcome != operationref.OutcomeCommitted {
				break
			}
		}
	}
	phase, outcome, reason := "COMPLETED", operationref.OutcomeCommitted, ""
	if progress.GroupsDone != progress.TotalGroups {
		phase, outcome, reason = suiteOutcome(runCtx, pathErr)
	}
	finished := time.Now().UTC()
	return publish(SuiteEvent{Kind: "finished", StartedAt: &started, FinishedAt: &finished}, phase, outcome, reason)
}

func checkCurrent(ctx context.Context, path Path) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	check, cancel := context.WithTimeout(ctx, ProbeBudget)
	defer cancel()
	return path.Current(check)
}

func suiteOutcome(ctx context.Context, pathErr error) (string, operationref.Outcome, string) {
	const failed = operationref.OutcomeFailed
	switch {
	case ctx.Err() == context.Canceled:
		return "CANCELED", failed, string(Canceled)
	case ctx.Err() == context.DeadlineExceeded:
		return "TIMEOUT", failed, string(Timeout)
	case errors.Is(pathErr, ErrGenerationChanged):
		return "PATH_RETIRED", failed, string(ErrGenerationChanged)
	case pathErr != nil:
		return "PATH_UNAVAILABLE", failed, pathReason(pathErr)
	default:
		return "COMPLETED", operationref.OutcomeCommitted, ""
	}
}

func projectedJob(ref operationref.Reference, sequence uint64, revision string, deadline time.Time, phase string, outcome operationref.Outcome, reason string) operationref.Job {
	job := operationref.ProjectJob(operationref.Change{Reference: ref, Revision: sequence, Phase: phase, OwnerPhase: phase,
		ExpectedRevision: revision, Outcome: outcome}.WithProblem(reason), nil, false)
	job.Deadline = deadline.Unix()
	job.CancelSupported = outcome == operationref.OutcomePending
	return job
}
