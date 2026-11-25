package blockcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/MalenkiySolovey/solovey-host/hostref"
	"github.com/MalenkiySolovey/solovey-host/operationref"
)

func TestSuitePreservesCatalogOrderAcrossBatchesAndGroupFailures(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, TCP)
	failed := cat.Groups[0]
	failed.ID = "failed"
	cat.Groups = []Group{failed, {ID: "disabled", Name: "Disabled", Disabled: true, Targets: failed.Targets}}
	large := Group{ID: "large", Name: "Large"}
	for i := range 35 {
		large.Targets = append(large.Targets, Target{Name: "Web", Host: fmt.Sprintf("web-%d.example", i), Probes: []Probe{TCP}})
	}
	cat.Groups = append(cat.Groups, large)
	for i := range 64 {
		cat.Groups = append(cat.Groups, Group{ID: fmt.Sprintf("saved-%d", i), Name: "Saved", Disabled: true, Targets: failed.Targets})
	}
	encoded, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	cat, err = DecodeCatalog(encoded)
	if err != nil {
		t.Fatalf("request byte budget should not imply count limits: %v", err)
	}
	req.GroupID, req.CatalogRevision = "", cat.Revision()
	var opens, resolves, dials, inflight, peak atomic.Int32
	blocked := make(chan struct{})
	path.Resolve = func(ctx context.Context, name string, _ Family, _ Probe) (Resolution, error) {
		resolves.Add(1)
		if name == "fixture.example" {
			return Resolution{}, errors.New("controlled resolution failure")
		}
		cur := inflight.Add(1)
		defer inflight.Add(-1)
		for last := peak.Load(); cur > last && !peak.CompareAndSwap(last, cur); last = peak.Load() {
		}
		if cur == probeBatchSize && dials.Load() == 0 {
			close(blocked)
		}
		select {
		case <-blocked:
		case <-ctx.Done():
			return Resolution{}, ctx.Err()
		}
		return Resolution{Addresses: []netip.Addr{fixtureAddr}, Context: "fixture-resolver"}, nil
	}
	path.DialTCP = func(_ context.Context, address netip.AddrPort) (net.Conn, SocketEvidence, error) {
		if address != netip.AddrPortFrom(fixtureAddr, 443) {
			t.Errorf("dial did not use admitted literal: %s", address)
		}
		dials.Add(1)
		client, endpoint := net.Pipe()
		_ = endpoint.Close()
		return client, SocketEvidence{}, nil
	}
	var events []SuiteEvent
	err = c.RunSuite(t.Context(), hostref.Local(), cat, SuiteRequest{RunRequest: req, All: true}, ProviderFunc(func(context.Context, hostref.Ref, PathSelection) (Path, error) {
		opens.Add(1)
		return path, nil
	}), func(ip netip.Addr) bool { return ip == fixtureAddr }, func(event SuiteEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil || opens.Load() != 1 || peak.Load() != probeBatchSize || resolves.Load() != 36 || dials.Load() != 35 {
		t.Fatalf("suite did not traverse bounded batches through one path: err=%v opens=%d peak=%d resolves=%d dials=%d", err, opens.Load(), peak.Load(), resolves.Load(), dials.Load())
	}
	start, finish := events[0], events[len(events)-1]
	if start.Kind != "started" || !start.Job.CancelSupported || start.Progress.ProbesDone != 0 || finish.Kind != "finished" ||
		finish.Job.CancelSupported || finish.Job.Outcome != operationref.OutcomeCommitted || finish.Progress != (SuiteProgress{2, 2, 36, 36}) {
		t.Fatalf("invalid job boundaries: start=%+v finish=%+v", start, finish)
	}
	var reports []string
	var largeRows []int
	for i, event := range events {
		if event.Job.OperationID != start.Job.OperationID || event.Job.Revision != uint64(i+1) {
			t.Fatalf("suite changed jobs or emitted out of sequence: %+v", event)
		}
		seen := len(event.Rows)
		if seen != 0 && (seen > probeBatchSize || event.Kind != "progress") {
			t.Fatalf("not a bounded incremental update: %+v", event)
		}
		if event.Group == nil {
			continue
		}
		if event.Report != nil {
			reports = append(reports, event.Report.GroupID)
			if event.Report.Evidence.Generation != "core-generation" {
				t.Fatalf("unexpected report path: %+v", event.Report)
			}
		}
		for _, row := range event.Rows {
			if event.Group.ID == "failed" && row.Status != ResolutionFailed {
				t.Fatalf("individual failure not captured: %+v", row)
			}
			if event.Group.ID == "large" {
				if row.Status != OK || row.Proof == nil {
					t.Fatalf("missing observation: %+v", row)
				}
				largeRows = append(largeRows, row.Target)
			}
		}
	}
	if !slices.Equal(reports, []string{"failed", "large"}) || len(largeRows) != 35 || !slices.IsSorted(largeRows) {
		t.Fatalf("lost groups or definition order: %v %v", reports, largeRows)
	}
}

func TestSuiteRetirementKeepsCompletedGroupsAndNeverReopens(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, DNS)
	cat.Groups = append(cat.Groups, Group{ID: "second", Name: "Second", Targets: cat.Groups[0].Targets})
	req.GroupID, req.CatalogRevision = "", cat.Revision()
	var drift atomic.Bool
	var opens, resolves atomic.Int32
	path.Current = func(context.Context) error {
		if drift.Load() {
			return ErrGenerationChanged
		}
		return nil
	}
	resolve := path.Resolve
	path.Resolve = func(ctx context.Context, host string, family Family, probe Probe) (Resolution, error) {
		resolves.Add(1)
		return resolve(ctx, host, family, probe)
	}
	var terminal SuiteEvent
	err := c.RunSuite(t.Context(), hostref.Local(), cat, SuiteRequest{RunRequest: req, All: true}, ProviderFunc(func(context.Context, hostref.Ref, PathSelection) (Path, error) {
		opens.Add(1)
		return path, nil
	}), func(netip.Addr) bool { return true }, func(event SuiteEvent) error {
		if event.Kind == "group" && event.Group.ID == "fixture" && event.Group.Completed == 1 {
			drift.Store(true)
		}
		terminal = event
		return nil
	})
	if err != nil || opens.Load() != 1 || resolves.Load() != 1 || terminal.Kind != "finished" || terminal.Job.Phase != "PATH_RETIRED" ||
		terminal.Job.Problem == nil || terminal.Job.Problem.Code != string(ErrGenerationChanged) || terminal.Progress != (SuiteProgress{1, 2, 1, 2}) {
		t.Fatalf("retired path ran or rewrote work: %v %+v", err, terminal)
	}
}

func TestSuiteCancelPreservesBoundaryAndAllowsIndependentRecheck(t *testing.T) {
	c, cat, req, path := fixture(t, Outbound, DNS)
	var terminal SuiteEvent
	operation := ""
	var resolves atomic.Int32
	resolve := path.Resolve
	path.Resolve = func(ctx context.Context, host string, family Family, probe Probe) (Resolution, error) {
		resolves.Add(1)
		return resolve(ctx, host, family, probe)
	}
	err := c.RunSuite(t.Context(), hostref.Local(), cat, SuiteRequest{RunRequest: req}, fixtureProvider(path), func(netip.Addr) bool { return true }, func(event SuiteEvent) error {
		if event.Kind == "started" {
			operation = event.Job.OperationID
			if err := c.CancelSuite(hostref.Local(), "unrelated"); !errors.Is(err, ErrRunNotFound) {
				t.Fatalf("cancelled nonmatching job: %v", err)
			}
			if _, err := c.Run(t.Context(), hostref.Local(), cat, req, fixtureProvider(path), func(netip.Addr) bool { return true }); !errors.Is(err, ErrBusy) {
				t.Fatalf("legacy and suite requests used different gates: %v", err)
			}
			if err := c.CancelSuite(hostref.Local(), operation); err != nil {
				return err
			}
		}
		terminal = event
		return nil
	})
	if err != nil || resolves.Load() != 0 || terminal.Kind != "finished" || terminal.Job.Phase != "CANCELED" || terminal.Progress.ProbesDone != 0 {
		t.Fatalf("cancel did not stop the run: %v %+v", err, terminal)
	}
	if err := c.CancelSuite(hostref.Local(), operation); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("finished job was retained: %v", err)
	}
	if report := runFixture(t, c, cat, req, path); report.Results[0].Status != DNSResponse || resolves.Load() != 1 {
		t.Fatalf("failed independent recheck: %+v", report)
	}
}
