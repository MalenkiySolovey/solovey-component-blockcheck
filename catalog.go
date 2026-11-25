package blockcheck

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MalenkiySolovey/solovey-host/componenthost/health"
)

type Probe string

const (
	DNS       Probe = "dns"
	TCP       Probe = "tcp"
	TLS       Probe = "tls"
	TLS12     Probe = "tls12"
	TLS13     Probe = "tls13"
	HTTP      Probe = "http"
	HTTPS     Probe = "https"
	HTTPData  Probe = "http-data"
	HTTPSData Probe = "https-data"
	DNSUDP    Probe = "dns-udp"
	DNSTCP    Probe = "dns-tcp"
	DoT       Probe = "dot"
	DoH       Probe = "doh"
	DoQ       Probe = "doq"
	DoH3      Probe = "doh3"
	QUIC      Probe = "quic"
	HTTP3     Probe = "http3"
	STUN      Probe = "stun"
	ICMP      Probe = "icmp"
)

var knownProbes = [...]Probe{DNS, TCP, TLS, TLS12, TLS13, HTTP, HTTPS, HTTPData, HTTPSData, DNSUDP, DNSTCP, DoT, DoH, DoQ, DoH3, QUIC, HTTP3, STUN, ICMP}

const (
	CatalogSchema   = "solovey.blockcheck.groups/v1"
	TransferSchema  = "solovey.blockcheck.group/v1"
	ReferenceCommit = "47a1b0d7c4acb0426bdaf0c2f03a40df458a7e91"
	MaxCatalogBytes = 128 << 10
)

var (
	ErrInvalidGroup    = errors.New("blockcheck_invalid_group")
	ErrInvalidCatalog  = errors.New("blockcheck_invalid_catalog")
	ErrGroupNotFound   = errors.New("blockcheck_group_not_found")
	ErrStaleCatalog    = errors.New("blockcheck_stale_catalog")
	ErrCatalogCapacity = errors.New("blockcheck_catalog_capacity")
)

//go:embed defaults.json
var frozenGroups []byte

type TemplateOrigin struct {
	Template string `json:"template"`
	Commit   string `json:"commit"`
}

type Target struct {
	Name   string  `json:"name"`
	Host   string  `json:"host"`
	Role   string  `json:"role"`
	Port   uint16  `json:"port,omitempty"`
	Probes []Probe `json:"probes"`
}

type Group struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Origin      *TemplateOrigin `json:"origin,omitempty"`
	Disabled    bool            `json:"disabled,omitempty"`
	Targets     []Target        `json:"targets"`
}

type Catalog struct {
	Schema string  `json:"schema"`
	Groups []Group `json:"groups"`
}

type CatalogView struct {
	Catalog
	Revision  string  `json:"revision"`
	Templates []Group `json:"templates"`
	Probes    []Probe `json:"probes"`
}

type GroupTransfer struct {
	Schema string `json:"schema"`
	Group  Group  `json:"group"`
}

type CatalogChange struct {
	Action           string         `json:"action"`
	ExpectedRevision string         `json:"expectedRevision"`
	ID               string         `json:"id,omitempty"`
	Group            *Group         `json:"group,omitempty"`
	Transfer         *GroupTransfer `json:"transfer,omitempty"`
	Order            []string       `json:"order,omitempty"`
}

func Templates() []Group {
	var groups []Group
	if err := json.Unmarshal(frozenGroups, &groups); err != nil {
		panic(err)
	}
	for i := range groups {
		groups[i].Origin = &TemplateOrigin{Template: groups[i].ID, Commit: ReferenceCommit}
	}
	return groups
}

// Unset storage reads as immutable defaults. An explicitly saved empty group
// list stays empty; a future change to defaults never overwrites a saved list.
func DecodeCatalog(data []byte) (Catalog, error) {
	if len(data) == 0 {
		return Catalog{Schema: CatalogSchema, Groups: Templates()}, nil
	}
	if len(data) > MaxCatalogBytes {
		return Catalog{}, ErrCatalogCapacity
	}
	var catalog Catalog
	if decode(data, &catalog) != nil || catalog.Validate() != nil {
		return Catalog{}, ErrInvalidCatalog
	}
	return catalog, nil
}

func decode(data []byte, target any) error {
	if !utf8.Valid(data) {
		return ErrInvalidCatalog
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrInvalidCatalog
	}
	return nil
}

func (c Catalog) View() CatalogView {
	return CatalogView{Catalog: c, Revision: c.Revision(), Templates: Templates(), Probes: slices.Clone(knownProbes[:])}
}

func (c Catalog) Revision() string { return revision(c) }
func (g Group) Revision() string   { return revision(g) }

func revision(value any) string {
	data, _ := json.Marshal(value)
	return health.Revision(string(data))
}

func (c Catalog) Group(id string) (Group, bool) {
	i := slices.IndexFunc(c.Groups, func(g Group) bool { return g.ID == id })
	if i < 0 {
		return Group{}, false
	}
	return c.Groups[i], true
}

func (c Catalog) Validate() error {
	if c.Schema != CatalogSchema || c.Groups == nil {
		return ErrInvalidCatalog
	}
	if data, err := json.Marshal(c); err != nil || len(data) > MaxCatalogBytes {
		return ErrCatalogCapacity
	}
	seen := make(map[string]bool, len(c.Groups))
	for _, group := range c.Groups {
		if seen[group.ID] || !validID(group.ID) || group.validate() != nil || !validOrigin(group.Origin) {
			return ErrInvalidGroup
		}
		seen[group.ID] = true
	}
	return nil
}

func validOrigin(origin *TemplateOrigin) bool {
	if origin == nil {
		return true
	}
	// Historical template revisions are valid provenance, not active defaults.
	return validID(origin.Template) && len(origin.Commit) == 40 && strings.Trim(origin.Commit, "0123456789abcdef") == ""
}

func validID(id string) bool {
	return id != "" && len(id) <= 64 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func validText(text string, limit int, required bool) bool {
	return (!required || text != "") && strings.TrimSpace(text) == text && len(text) <= limit && utf8.ValidString(text) &&
		!strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) })
}

func (g Group) validate() error {
	if !validText(g.Name, 96, true) || !validText(g.Description, 384, false) || len(g.Targets) == 0 {
		return ErrInvalidGroup
	}
	seen := map[string]bool{}
	for _, target := range g.Targets {
		// A single endpoint can carry multiple probes without duplicate rows.
		key := target.Host + "\x00" + target.Role
		if seen[key] || target.validate() != nil {
			return ErrInvalidGroup
		}
		seen[key] = true
	}
	return nil
}

func (t Target) validate() error {
	if !validText(t.Name, 96, true) || !validText(t.Role, 128, false) || !validHost(t.Host) || len(t.Probes) == 0 || len(t.Probes) > len(knownProbes) {
		return ErrInvalidGroup
	}
	seen := map[Probe]bool{}
	for _, probe := range t.Probes {
		if seen[probe] || !slices.Contains(knownProbes[:], probe) || (t.Port != 0 && probe != STUN) {
			return ErrInvalidGroup
		}
		seen[probe] = true
	}
	if seen[STUN] && t.Port != 3478 && t.Port != 19302 {
		return ErrInvalidGroup
	}
	return nil
}

func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return basePublicAddress(addr) && addr.String() == host
	}
	if host == "" || len(host) > 253 || strings.ToLower(host) != host || !strings.Contains(host, ".") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	tld := labels[len(labels)-1]
	return len(tld) >= 2 && strings.ContainsAny(tld, "abcdefghijklmnopqrstuvwxyz")
}

func basePublicAddress(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

func (g Group) Export() GroupTransfer { return GroupTransfer{Schema: TransferSchema, Group: g} }

func (c Catalog) Apply(change CatalogChange) (Catalog, error) {
	if change.ExpectedRevision != c.Revision() {
		return Catalog{}, ErrStaleCatalog
	}
	result := Catalog{Schema: CatalogSchema, Groups: slices.Clone(c.Groups)}
	i := slices.IndexFunc(c.Groups, func(g Group) bool { return g.ID == change.ID })
	switch change.Action {
	case "create", "import", "clone":
		var group Group
		switch change.Action {
		case "create":
			if change.Group == nil {
				return Catalog{}, ErrInvalidGroup
			}
			group = *change.Group
			group.Origin = nil
		case "import":
			if change.Transfer == nil || change.Transfer.Schema != TransferSchema {
				return Catalog{}, ErrInvalidGroup
			}
			group = change.Transfer.Group
			// A transfer is not an authenticated receipt for template origin.
			group.Origin = nil
		case "clone":
			if i < 0 {
				return Catalog{}, ErrGroupNotFound
			}
			group = c.Groups[i]
			if change.Group != nil {
				group.Name = change.Group.Name
			}
		}
		group.ID = newID("group-")
		result.Groups = append(result.Groups, group)
	case "edit":
		if i < 0 || change.Group == nil {
			return Catalog{}, ErrGroupNotFound
		}
		group := *change.Group
		group.ID, group.Origin = c.Groups[i].ID, c.Groups[i].Origin
		result.Groups[i] = group
	case "delete":
		if i < 0 {
			return Catalog{}, ErrGroupNotFound
		}
		result.Groups = slices.Delete(result.Groups, i, i+1)
	case "toggle":
		if i < 0 {
			return Catalog{}, ErrGroupNotFound
		}
		result.Groups[i].Disabled = !c.Groups[i].Disabled
	case "order":
		if len(change.Order) != len(c.Groups) {
			return Catalog{}, ErrInvalidCatalog
		}
		for index, id := range change.Order {
			group, ok := c.Group(id)
			if !ok {
				return Catalog{}, ErrGroupNotFound
			}
			result.Groups[index] = group
		}
	case "restore":
		for _, template := range Templates() {
			if template.ID != change.ID {
				continue
			}
			if i < 0 {
				result.Groups = append(result.Groups, template)
			} else {
				result.Groups[i] = template
			}
			goto verify
		}
		return Catalog{}, ErrGroupNotFound
	default:
		return Catalog{}, ErrInvalidCatalog
	}
verify:
	return result, result.Validate()
}

func newID(prefix string) string {
	var value [16]byte
	rand.Read(value[:])
	return prefix + hex.EncodeToString(value[:])
}
