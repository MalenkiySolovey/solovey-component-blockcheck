package blockcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func TestTemplateCatalogAndManifest(t *testing.T) {
	m := Manifest()
	if m.ID != ID || m.DefaultEnabled || m.Database.SchemaVersion != "3" || !slices.Equal(m.Database.Tables, []string{CatalogGroupTable, HistoryGroupTable, HistoryRunTable}) ||
		!slices.Equal(m.Database.Settings, []string{CatalogRevisionSettingKey, CatalogSettingKey, HistorySettingKey}) {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	c, err := DecodeCatalog(nil)
	if err != nil || c.Validate() != nil || len(c.Groups) != 16 {
		t.Fatalf("invalid frozen defaults: %+v %v", c, err)
	}
	for _, id := range []string{"youtube", "discord", "stun-controls", "icmp-controls"} {
		g, ok := c.Group(id)
		if !ok || g.Origin == nil || g.Origin.Template != id || g.Origin.Commit != ReferenceCommit {
			t.Fatalf("missing source origin for %q", id)
		}
	}
	for _, data := range [][]byte{[]byte(`{"schema":"solovey.blockcheck.groups/v1","groups":null}`),
		[]byte(`{"schema":"solovey.blockcheck.groups/v1","groups":[],"ignored":true}`),
		[]byte(`{"schema":"solovey.blockcheck.groups/v1","groups":[]} {}`),
		{0xff}} {
		if _, err := DecodeCatalog(data); !errors.Is(err, ErrInvalidCatalog) {
			t.Fatalf("unexpected decode error %q: %v", data, err)
		}
	}
	if _, err := DecodeCatalog(bytes.Repeat([]byte{' '}, MaxCatalogBytes+1)); !errors.Is(err, ErrCatalogCapacity) {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(Catalog{Schema: CatalogSchema, Groups: []Group{}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := DecodeCatalog(encoded)
	if err != nil || len(empty.Groups) != 0 || empty.Revision() == c.Revision() {
		t.Fatal("explicitly empty catalog must not reseed")
	}
	for _, catalog := range []Catalog{c, empty, {}} {
		if catalog.Revision() != revision(catalog) {
			t.Fatal("catalog migration changed the v1 revision", catalog.Schema)
		}
	}
	selected, err := SelectedCatalog(c.Revision(), c.Groups[:1])
	if err != nil || selected.Revision() != c.Revision() {
		t.Fatalf("selection lost the full catalog revision: %v", err)
	}
	if _, err := selected.Apply(CatalogChange{Action: "delete", ID: selected.Groups[0].ID, ExpectedRevision: c.Revision()}); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("ran a catalog mutation with an incomplete selection: %v", err)
	}
}

func TestCatalogMutationsPreserveIdentityAndRevision(t *testing.T) {
	c, err := DecodeCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	savedRevision := c.Revision()
	orig, _ := c.Group("discord")
	draft := orig
	draft.Name, draft.ID, draft.Origin = "My Discord", "other", nil
	apply := func(change CatalogChange) {
		t.Helper()
		change.ExpectedRevision = c.Revision()
		var err error
		c, err = c.Apply(change)
		if err != nil {
			t.Fatal(err)
		}
	}
	apply(CatalogChange{Action: "edit", ID: orig.ID, Group: &draft})
	updated, _ := c.Group(orig.ID)
	if updated.ID != orig.ID || updated.Name != draft.Name || *updated.Origin != *orig.Origin {
		t.Fatalf("edit changed identity or origin: %+v", updated)
	}
	if _, err := c.Apply(CatalogChange{Action: "delete", ID: orig.ID, ExpectedRevision: savedRevision}); !errors.Is(err, ErrStaleCatalog) {
		t.Fatalf("stale change accepted: %v", err)
	}
	apply(CatalogChange{Action: "clone", ID: orig.ID, Group: &Group{Name: "Copy"}})
	copy := c.Groups[len(c.Groups)-1]
	if copy.ID == orig.ID || copy.Origin == nil || copy.Name != "Copy" {
		t.Fatalf("unexpected clone: %+v", copy)
	}
	transfer := updated.Export()
	apply(CatalogChange{Action: "import", Transfer: &transfer})
	imported := c.Groups[len(c.Groups)-1]
	if imported.ID == orig.ID || imported.ID == copy.ID || imported.Origin != nil || !slices.EqualFunc(imported.Targets, orig.Targets, func(a, b Target) bool {
		return a.Host == b.Host && slices.Equal(a.Probes, b.Probes)
	}) {
		t.Fatalf("import clobbered an ID or trusted external provenance: %+v", imported)
	}
	apply(CatalogChange{Action: "delete", ID: orig.ID})
	if _, ok := c.Group(orig.ID); ok {
		t.Fatal("deleted default reappeared")
	}
	apply(CatalogChange{Action: "restore", ID: orig.ID})
	order := make([]string, len(c.Groups))
	for i, group := range c.Groups {
		order[len(order)-1-i] = group.ID
	}
	apply(CatalogChange{Action: "order", Order: order})
	if c.Groups[0].Revision() != orig.Revision() {
		t.Fatal("restore did not restore exact current template")
	}
}

func TestGroupSyntaxCannotNameInternalPaths(t *testing.T) {
	for _, host := range []string{"http://example.com", "example.com/path", "u@example.com", "singlelabel", "localhost", "x.localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1", "2001:4860::1%eth0", "999.999.999.999"} {
		if validHost(host) {
			t.Errorf("unsafe target syntax accepted: %s", host)
		}
	}
}

func TestCatalogDistinguishesSTUNPortsOnOneHost(t *testing.T) {
	c, err := DecodeCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	group := Group{Name: "Voice endpoints", Targets: []Target{
		{Name: "Default STUN", Host: "stun.example", Role: "voice", Port: 3478, Probes: []Probe{STUN}},
		{Name: "Alternate STUN", Host: "stun.example", Role: "voice", Port: 19302, Probes: []Probe{STUN}},
	}}
	change := CatalogChange{Action: "create", ExpectedRevision: c.Revision(), Group: &group}
	updated, err := c.Apply(change)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeCatalog(encoded)
	if err != nil {
		t.Fatal(err)
	}
	targets := restored.Groups[len(restored.Groups)-1].Targets
	if len(targets) != 2 || targets[0].Port != 3478 || targets[1].Port != 19302 {
		t.Fatalf("STUN ports were not preserved: %+v", targets)
	}
	for _, port := range []uint16{3478, 3479} {
		group.Targets[1].Port = port
		if _, err := c.Apply(change); !errors.Is(err, ErrInvalidGroup) {
			t.Fatalf("accepted duplicate or unadmitted STUN port %d: %v", port, err)
		}
	}
}
