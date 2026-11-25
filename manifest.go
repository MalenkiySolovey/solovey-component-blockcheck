// Package blockcheck owns diagnostic definitions, manual run intent and results.
// The installing host supplies admission, storage and effective path owners.
package blockcheck

import (
	_ "embed"

	"github.com/MalenkiySolovey/solovey-host/componenthost/manifest"
)

const ID = "blockcheck"
const CatalogSettingKey = "blockcheckGroupsV1"

//go:embed component.json
var descriptor []byte

func Manifest() manifest.Manifest { return manifest.MustFromJSON(descriptor) }
