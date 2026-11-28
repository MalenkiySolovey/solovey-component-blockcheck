package blockcheck

import (
	"encoding/json"
	"errors"
	"time"
)

// MaxHistoryBytes is the compatibility limit for the old settings row.
const MaxHistoryBytes = 512 << 10
const MaxHistoryAge = 14 * 24 * time.Hour

// A group detail must fit in a bounded history response. This is not an
// aggregate storage limit: one large group cannot displace other groups or runs.
const MaxHistoryGroupBytes = 1 << 20

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

// Redact also applies to legacy rows entering the new storage layout.
func (g *HistoryGroup) Redact() {
	for i, row := range g.Report.Results {
		g.Report.Results[i] = historyResult(row)
	}
	if g.Report.Results == nil {
		g.Report.Results = []Result{}
	}
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
	Hidden     int            `json:"hidden,omitempty"` // retained, but not included in this response
}

type History struct {
	Version int          `json:"version"`
	Runs    []HistoryRun `json:"runs"`
	Next    string       `json:"next,omitempty"`
	Paged   bool         `json:"paged,omitempty"`
}

func DecodeHistory(data []byte, now time.Time) (History, error) {
	h := History{Version: 1, Runs: []HistoryRun{}}
	if len(data) == 0 {
		return h, nil
	}
	if len(data) > MaxHistoryBytes || json.Unmarshal(data, &h) != nil || h.Version != 1 {
		return History{}, ErrInvalidHistory
	}
	result := History{Version: 1, Runs: []HistoryRun{}}
	oldest := now.Add(-MaxHistoryAge)
	for _, run := range h.Runs {
		if run.ID != "" && !run.StartedAt.IsZero() && !run.FinishedAt.Before(run.StartedAt) && !run.FinishedAt.Before(oldest) {
			result.Runs = append(result.Runs, run)
		}
	}
	return result, nil
}

// HistoryCapture observes the existing stream without scheduling work. It
// hands off redacted groups one at a time to the durable owner. It never keeps
// all probe detail for a Check All in memory or labels truncated groups complete.
type HistoryCapture struct {
	run      HistoryRun
	targets  map[string][]Target
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
	targets := make(map[string][]Target, len(catalog.Groups))
	for _, group := range catalog.Groups {
		if request.All && !group.Disabled || !request.All && group.ID == request.GroupID {
			run.GroupIDs = append(run.GroupIDs, group.ID)
			targets[group.ID] = group.Targets
		}
	}
	return &HistoryCapture{run: run, targets: targets}
}

// Observe returns metadata at finish or a completed (possibly canceled) group.
func (c *HistoryCapture) Observe(event SuiteEvent) (*HistoryRun, *HistoryGroup) {
	switch event.Kind {
	case "started":
		if event.StartedAt != nil {
			c.run.StartedAt = *event.StartedAt
		}
		c.run.ID = event.Job.OperationID
	case "progress":
		if event.Group == nil || c.oversize {
			break
		}
		c.group = event.Group.ID
		for _, row := range event.Rows {
			row = historyResult(row)
			data, err := json.Marshal(row)
			if err != nil || c.bytes+len(data)+1 > MaxHistoryGroupBytes {
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
		return nil, c.finishGroup(event)
	case "finished":
		if event.FinishedAt != nil {
			c.run.FinishedAt = *event.FinishedAt
		}
		c.run.Phase, c.run.Progress = event.Job.Phase, event.Progress
		return &c.run, nil
	}
	return nil, nil
}

func historyResult(row Result) Result {
	row.AttemptedAddress, row.Proof = "", nil
	row.Socket = historySocket(row.Socket)
	row.DNSSocket = historySocket(row.DNSSocket)
	return row
}

func historySocket(socket *SocketEvidence) *SocketEvidence {
	if socket == nil || socket.Egress == "" && !socket.OutsidePanel {
		return nil
	}
	return &SocketEvidence{Egress: socket.Egress, OutsidePanel: socket.OutsidePanel, RouteSelectionOnly: socket.RouteSelectionOnly}
}

func (c *HistoryCapture) finishGroup(event SuiteEvent) *HistoryGroup {
	report := *event.Report
	targets, exists := c.targets[event.Group.ID]
	item := HistoryGroup{Report: report}
	defer c.resetGroup()
	// Count the group's metadata separately; its result rows were counted on
	// arrival. Discard the entire body if it cannot be retained as one unit.
	if exists && !c.oversize && c.group == event.Group.ID {
		for _, target := range targets {
			item.Targets = append(item.Targets, HistoryTarget{Name: target.Name, Host: target.Host, Role: target.Role, Port: target.Port})
		}
		item.Report.Findings = c.findings
		meta, err := json.Marshal(item)
		if err == nil && c.bytes+len(meta)+1 <= MaxHistoryGroupBytes {
			item.Report.Results = c.rows
			if item.Report.Results == nil {
				item.Report.Results = []Result{}
			}
			return &item
		}
	}
	c.run.Omitted++
	return nil
}

func (c *HistoryCapture) resetGroup() {
	c.group, c.rows, c.findings, c.bytes, c.oversize = "", nil, nil, 0, false
}
