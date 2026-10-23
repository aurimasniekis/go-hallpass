// Package groups manages named groups and key/value labels used by policy selectors (HP-POL-003).
package groups

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"regexp"
	"slices"
	"sort"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Group kinds.
const (
	KindAgent    = "agent"
	KindServer   = "server"
	KindOperator = "operator"
)

// Label entity types.
const (
	EntityAgent  = "agent"
	EntityServer = "server"
	EntityRole   = "role"
)

// Limits.
const (
	MaxLabels          = 64
	MaxGroupsPerEntity = 64
)

var (
	groupNameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	labelKeyRE   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*/)?[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?$`)
	labelValueRE = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?)?$`)
)

// ValidGroupName reports whether name is a valid group name.
func ValidGroupName(name string) bool { return groupNameRE.MatchString(name) }

// ValidateLabels checks keys and values (Kubernetes-style syntax) and the label count.
func ValidateLabels(v *apperr.Validation, field string, labels map[string]string) {
	if len(labels) > MaxLabels {
		v.Add(field, "at most %d labels", MaxLabels)
	}
	for k, val := range labels {
		if len(k) > 253 || !labelKeyRE.MatchString(k) {
			v.Add(field, "invalid label key %q", k)
		}
		if !labelValueRE.MatchString(val) {
			v.Add(field, "invalid value for label %q", k)
		}
	}
}

// ValidateGroupNames checks names and the count.
func ValidateGroupNames(v *apperr.Validation, field string, names []string) {
	if len(names) > MaxGroupsPerEntity {
		v.Add(field, "at most %d groups", MaxGroupsPerEntity)
	}
	for _, n := range names {
		if !ValidGroupName(n) {
			v.Add(field, "invalid group name %q", n)
		}
	}
}

// Normalize returns sorted, de-duplicated names.
func Normalize(names []string) []string {
	out := slices.Clone(names)
	sort.Strings(out)
	return slices.Compact(out)
}

// Group is a named group.
type Group struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Ensure returns the IDs for the given group names of kind, creating missing groups inside tx.
func Ensure(ctx context.Context, tx *store.Tx, kind string, names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, n := range Normalize(names) {
		g, err := tx.Q.GetGroupByName(ctx, db.GetGroupByNameParams{Kind: kind, Name: n})
		switch {
		case err == nil:
			out = append(out, g.ID)
		case errors.Is(err, sql.ErrNoRows):
			id := ids.New(ids.Group)
			if err := tx.Q.InsertGroup(ctx, db.InsertGroupParams{ID: id, Kind: kind, Name: n, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}); err != nil {
				return nil, err
			}
			out = append(out, id)
		default:
			return nil, err
		}
	}
	return out, nil
}

// SetLabels replaces the labels of an entity inside tx.
func SetLabels(ctx context.Context, tx *store.Tx, entityType, entityID string, labels map[string]string) error {
	if err := tx.Q.DeleteLabels(ctx, db.DeleteLabelsParams{EntityType: entityType, EntityID: entityID}); err != nil {
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		if err := tx.Q.InsertLabel(ctx, db.InsertLabelParams{EntityType: entityType, EntityID: entityID, Key: k, Value: labels[k]}); err != nil {
			return err
		}
	}
	return nil
}

// Labels reads the labels of one entity.
func Labels(ctx context.Context, q *db.Queries, entityType, entityID string) (map[string]string, error) {
	rows, err := q.ListLabels(ctx, db.ListLabelsParams{EntityType: entityType, EntityID: entityID})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out, nil
}

// AllLabels reads labels of every entity of a type, keyed by entity ID.
func AllLabels(ctx context.Context, q *db.Queries, entityType string) (map[string]map[string]string, error) {
	rows, err := q.ListAllLabels(ctx, entityType)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, r := range rows {
		if out[r.EntityID] == nil {
			out[r.EntityID] = map[string]string{}
		}
		out[r.EntityID][r.Key] = r.Value
	}
	return out, nil
}

// List returns groups of a kind.
func List(ctx context.Context, q *db.Queries, kind string) ([]Group, error) {
	rows, err := q.ListGroups(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(rows))
	for _, r := range rows {
		out = append(out, Group{ID: r.ID, Kind: r.Kind, Name: r.Name, Description: r.Description})
	}
	return out, nil
}
