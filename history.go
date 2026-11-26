package blockcheck

import (
	"encoding/json"
	"errors"
	"time"
)

// History is derived evidence, kept independently of the editable catalog.
// The per-run byte budget leaves room for two comparable snapshots.
const MaxHistoryBytes = 512 << 10
const MaxHistoryAge = 14 * 24 * time.Hour
const maxHistoryRunBytes = MaxHistoryBytes/2 - 128

var ErrInvalidHistory = errors.New("blockcheck_history_invalid")

type HistoryTarget struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Role string `json:"role"`
	Port uint16 `json:"port,omitempty"`
}

type HistoryGroup struct {
	Report  Report          `json:"report"`
	Targets []HistoryTarget `json:"targets"`
}

type HistoryRun struct {
	ID         string         `json:"id"`
	All        bool           `json:"all"`
	GroupIDs   []string       `json:"groupIds"`
	Path       PathSelection  `json:"path"`
	Family     Family         `json:"family"`
	Depth      Depth          `json:"depth"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt time.Time      `json:"finishedAt"`
	Phase      string         `json:"phase"`
	Progress   SuiteProgress  `json:"progress"`
	Groups     []HistoryGroup `json:"groups"`
	Omitted    int            `json:"omitted,omitempty"`
}

type History struct {
	Version int          `json:"version"`
	Runs    []HistoryRun `json:"runs"`
}

func DecodeHistory(data []byte, now time.Time) (History, error) {
	h := History{Version: 1, Runs: []HistoryRun{}}
	if len(data) == 0 {
		return h, nil
	}
	if len(data) > MaxHistoryBytes || json.Unmarshal(data, &h) != nil || h.Version != 1 {
		return History{}, ErrInvalidHistory
	}
	return h.retained(now), nil
}

func (h History) retained(now time.Time) History {
	result := History{Version: 1, Runs: []HistoryRun{}}
	oldest := now.Add(-MaxHistoryAge)
	for _, run := range h.Runs {
		if run.ID != "" && !run.StartedAt.IsZero() && !run.FinishedAt.Before(run.StartedAt) && !run.FinishedAt.Before(oldest) {
			result.Runs = append(result.Runs, run)
		}
	}
	return result
}

func (h History) WithRun(run HistoryRun, now time.Time) ([]byte, error) {
	size, err := json.Marshal(run)
	if err != nil || len(size) > maxHistoryRunBytes || run.ID == "" || run.StartedAt.IsZero() || run.FinishedAt.Before(run.StartedAt) {
		return nil, ErrInvalidHistory
	}
	h = h.retained(now)
	retained := History{Version: 1, Runs: []HistoryRun{run}}
	remaining := MaxHistoryBytes - len(size) - 128
	for _, previous := range h.Runs {
		if previous.ID == run.ID {
			continue
		}
		data, err := json.Marshal(previous)
		if err != nil || len(data)+1 > remaining {
			break
		}
		retained.Runs = append(retained.Runs, previous)
		remaining -= len(data) + 1
	}
	return json.Marshal(retained)
}

// HistoryCapture observes the existing stream without scheduling work. It
// retains whole group reports or marks their details omitted, never passing
// off a truncated list of probes as a complete run.
type HistoryCapture struct {
	run      HistoryRun
	catalog  Catalog
	bytes    int
	group    string
	rows     []Result
	findings []GroupFinding
	oversize bool
}

func NewHistoryCapture(catalog Catalog, request SuiteRequest) *HistoryCapture {
	run := HistoryRun{All: request.All, Path: request.Path, Family: request.Family, Depth: request.Depth, Groups: []HistoryGroup{}}
	if run.Depth == "" {
		run.Depth = Quick
	}
	for _, group := range catalog.Groups {
		if request.All && !group.Disabled || !request.All && group.ID == request.GroupID {
			run.GroupIDs = append(run.GroupIDs, group.ID)
		}
	}
	return &HistoryCapture{run: run, catalog: catalog}
}

func (c *HistoryCapture) Observe(event SuiteEvent) *HistoryRun {
	switch event.Kind {
	case "started":
		if event.StartedAt != nil {
			c.run.StartedAt = *event.StartedAt
		}
		c.run.ID = event.Job.OperationID
		meta, _ := json.Marshal(c.run)
		c.bytes = len(meta) + 256 // terminal metadata and JSON delimiters
	case "progress":
		if event.Group == nil || c.oversize {
			break
		}
		c.group = event.Group.ID
		for _, row := range event.Rows {
			row.AttemptedAddress, row.Proof = "", nil
			// The report may still distinguish an observed egress from an
			// requested tag. Link-layer details are not needed in history.
			row.Socket = historySocket(row.Socket)
			row.DNSSocket = historySocket(row.DNSSocket)
			data, err := json.Marshal(row)
			if err != nil || c.bytes+len(data)+1 > maxHistoryRunBytes {
				c.oversize = true
				break
			}
			c.bytes += len(data) + 1
			c.rows = append(c.rows, row)
		}
		if !c.oversize {
			c.findings = append(c.findings, event.Findings...)
		}
	case "group":
		if event.Group == nil || event.Report == nil {
			break
		}
		c.finishGroup(event)
	case "finished":
		if event.FinishedAt != nil {
			c.run.FinishedAt = *event.FinishedAt
		}
		c.run.Phase, c.run.Progress = event.Job.Phase, event.Progress
		return &c.run
	}
	return nil
}

func historySocket(socket *SocketEvidence) *SocketEvidence {
	if socket == nil || socket.Egress == "" && !socket.OutsidePanel {
		return nil
	}
	return &SocketEvidence{Egress: socket.Egress, OutsidePanel: socket.OutsidePanel, RouteSelectionOnly: socket.RouteSelectionOnly}
}

func (c *HistoryCapture) finishGroup(event SuiteEvent) {
	report := *event.Report
	group, exists := c.catalog.Group(event.Group.ID)
	item := HistoryGroup{Report: report}
	// Count the group's metadata separately; its result rows were counted on
	// arrival. Discard the entire body if it cannot be retained as one unit.
	if exists && !c.oversize && c.group == event.Group.ID {
		for _, target := range group.Targets {
			item.Targets = append(item.Targets, HistoryTarget{Name: target.Name, Host: target.Host, Role: target.Role, Port: target.Port})
		}
		item.Report.Findings = c.findings
		meta, err := json.Marshal(item)
		if err == nil && c.bytes+len(meta)+1 <= maxHistoryRunBytes {
			item.Report.Results = c.rows
			if item.Report.Results == nil {
				item.Report.Results = []Result{}
			}
			c.run.Groups = append(c.run.Groups, item)
			c.bytes += len(meta) + 1
			c.resetGroup()
			return
		}
	}
	c.run.Omitted++
	for _, row := range c.rows {
		data, _ := json.Marshal(row)
		c.bytes -= len(data) + 1
	}
	c.resetGroup()
}

func (c *HistoryCapture) resetGroup() {
	c.group, c.rows, c.findings, c.oversize = "", nil, nil, false
}
