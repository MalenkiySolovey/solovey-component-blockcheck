package blockcheck

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MalenkiySolovey/solovey-host/operationref"
)

func TestHistoryCaptureIsBoundedAndDoesNotMutateLiveEvidence(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)
	finish := start.Add(time.Second)
	catalog := Catalog{Groups: []Group{{ID: "voice", Targets: []Target{{Name: "Voice test", Host: "fixture.example", Role: "connection control"}}},
		{ID: "skip", Disabled: true}}}
	capture := NewHistoryCapture(catalog, SuiteRequest{All: true, RunRequest: RunRequest{Family: IPv4}})
	capture.Observe(SuiteEvent{Kind: "started", StartedAt: &start, Job: operationref.Job{Reference: operationref.NewReference(ID, "catalog", "run-fixture")}})
	group := GroupProgress{ID: "voice", Completed: 2, Total: 3}
	row := Result{Cell: Cell{Target: 0, Probe: HTTPS}, TargetRef: "target", Stage: StageTLS, Status: ConnectionReset,
		AttemptedAddress: "9.9.9.9", Socket: &SocketEvidence{Egress: "snell", Interface: "fixture0"},
		DNSSocket: &SocketEvidence{Egress: "resolver-outbound", Interface: "fixture1"}}
	startMS := int64(0)
	timed := Result{Cell: Cell{Target: 0, Probe: HTTP3}, TargetRef: "target", Stage: StageHTTP, Status: HTTPResponse, HTTPStatus: 204, HTTPResponseStartMS: &startMS}
	capture.Observe(SuiteEvent{Kind: "progress", Group: &group, Rows: []Result{row, timed}})
	capture.Observe(SuiteEvent{Kind: "group", Group: &group, Report: &Report{GroupID: "voice", StartedAt: start, FinishedAt: finish}})
	run := capture.Observe(SuiteEvent{Kind: "finished", FinishedAt: &finish, Job: operationref.Job{Phase: "CANCELED"}})
	data, err := (History{}).WithRun(*run, finish)
	if err != nil || bytes.Contains(data, []byte(row.AttemptedAddress)) || bytes.Contains(data, []byte(row.Socket.Interface)) || bytes.Contains(data, []byte(row.DNSSocket.Interface)) {
		t.Fatalf("history retained network address or interface: %s (%v)", data, err)
	}
	if row.Socket.Interface != "fixture0" || row.AttemptedAddress != "9.9.9.9" {
		t.Fatal("history touched live evidence")
	}
	stored, err := DecodeHistory(data, finish)
	if err != nil || len(stored.Runs) != 1 || len(stored.Runs[0].Groups) != 1 || len(stored.Runs[0].GroupIDs) != 1 {
		t.Fatalf("bad history: %+v, %v", stored, err)
	}
	got := stored.Runs[0]
	if got.Phase != "CANCELED" || got.Depth != Quick || len(got.Groups[0].Report.Results) != 2 || got.Groups[0].Report.Results[0].Status != ConnectionReset || got.Groups[0].Targets[0].Role != "connection control" {
		t.Fatalf("lost partial evidence: %+v", got)
	}
	if stored := got.Groups[0].Report.Results[0]; stored.Socket.Egress != "snell" || stored.DNSSocket.Egress != "resolver-outbound" {
		t.Fatalf("lost comparable socket evidence: %+v", stored)
	}
	if duration := got.Groups[0].Report.Results[1].HTTPResponseStartMS; duration == nil || *duration != 0 {
		t.Fatal("history dropped an observed zero response-start duration")
	}
	if stripped := (Report{Results: []Result{row}}).Redacted(); stripped.Results[0].AttemptedAddress != "" {
		t.Fatal("copy retained the attempted address")
	}
}

func TestHistoryDropsOversizeGroupAsAUnitAndPrunesOldRuns(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)
	finish := start.Add(time.Second)
	capture := NewHistoryCapture(Catalog{Groups: []Group{{ID: "large"}, {ID: "small"}}}, SuiteRequest{All: true})
	capture.Observe(SuiteEvent{Kind: "started", StartedAt: &start, Job: operationref.Job{Reference: operationref.NewReference(ID, "catalog", "run-current")}})
	large := GroupProgress{ID: "large"}
	capture.Observe(SuiteEvent{Kind: "progress", Group: &large, Rows: []Result{{Status: OK}, {Reason: strings.Repeat("x", maxHistoryRunBytes)}}})
	capture.Observe(SuiteEvent{Kind: "group", Group: &large, Report: &Report{GroupID: "large"}})
	small := GroupProgress{ID: "small"}
	capture.Observe(SuiteEvent{Kind: "progress", Group: &small, Rows: []Result{{Status: OK}}})
	capture.Observe(SuiteEvent{Kind: "group", Group: &small, Report: &Report{GroupID: "small"}})
	run := capture.Observe(SuiteEvent{Kind: "finished", FinishedAt: &finish, Job: operationref.Job{Phase: "COMPLETED"}})
	if len(run.Groups) != 1 || run.Groups[0].Report.GroupID != "small" || run.Omitted != 1 {
		t.Fatalf("oversize group displaced small group: %+v", run)
	}
	old := start.Add(-MaxHistoryAge)
	current := History{Version: 1, Runs: []HistoryRun{{ID: "old", StartedAt: old, FinishedAt: old}}}
	data, err := current.WithRun(*run, finish)
	if err != nil || len(data) > MaxHistoryBytes || bytes.Contains(data, []byte("old")) {
		t.Fatalf("wrong retention: %s (%v)", data, err)
	}
}
