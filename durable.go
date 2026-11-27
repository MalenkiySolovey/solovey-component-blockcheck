package blockcheck

import (
	"context"
	"errors"
	"time"

	"github.com/MalenkiySolovey/solovey-host/componenthost/durable"
)

// CatalogOwner uses the existing Backend-owned transaction and restore ports.
type CatalogOwner struct{}

func validateCatalogScope(scope durable.Scope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if scope.OwnerID != ID || scope.SchemaVersion != "2" || scope.MigrationVersion != "2" {
		return errors.New("blockcheck catalog durable scope mismatch")
	}
	return nil
}

func (CatalogOwner) Migrate(ctx context.Context, port durable.Migration) error {
	if err := validateCatalogScope(port.Scope()); err != nil {
		return err
	}
	_, err := port.MigrateAndValidate(ctx)
	return err
}

func (CatalogOwner) RehearseRestore(ctx context.Context, port durable.Restore) error {
	if err := validateCatalogScope(port.Scope()); err != nil {
		return err
	}
	_, err := port.NormalizeRestore(ctx)
	return err
}

func (CatalogOwner) InspectDropAuthority(ctx context.Context, port durable.Inspection, now time.Time) (durable.AuthorityStatus, error) {
	if err := validateCatalogScope(port.Scope()); err != nil {
		return durable.AuthorityStatus{}, err
	}
	return port.InspectDropAuthority(ctx, now)
}

func (CatalogOwner) DropData(ctx context.Context, port durable.DataDrop) error {
	if err := validateCatalogScope(port.Scope()); err != nil {
		return err
	}
	_, err := port.DropOwnedData(ctx)
	return err
}
