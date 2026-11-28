// Package blockcheck owns diagnostic definitions, manual run intent and results.
// The installing host supplies admission, storage and effective path owners.
package blockcheck

import (
	_ "embed"

	"github.com/MalenkiySolovey/solovey-host/componenthost/manifest"
)

const ID = "blockcheck"
const CatalogSettingKey = "blockcheckGroupsV1"
const CatalogRevisionSettingKey = "blockcheckGroupsRevisionV2"
const CatalogGroupTable = "blockcheck_group_catalog_v2"
const HistorySettingKey = "blockcheckHistoryV1"
const HistoryRunTable = "blockcheck_history_run_v3"
const HistoryGroupTable = "blockcheck_history_group_v3"

//go:embed component.json
var descriptor []byte

func Manifest() manifest.Manifest { return manifest.MustFromJSON(descriptor) }
