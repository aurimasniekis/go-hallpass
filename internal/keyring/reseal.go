package keyring

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Column describes a sealed column for background re-encryption after a purpose-key rotation (HP-CRY-002).
type Column struct {
	Table, IDColumn, BlobColumn string
	Purpose                     Purpose
	// AAD returns the associated data the column was sealed with for a row ID.
	AAD func(id string) []byte
}

var identRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// FieldColumn is a column sealed with FieldAAD(table, column, id).
func FieldColumn(table, idColumn, blobColumn string, p Purpose) Column {
	return Column{Table: table, IDColumn: idColumn, BlobColumn: blobColumn, Purpose: p,
		AAD: func(id string) []byte { return FieldAAD(table, blobColumn, id) }}
}

// ResealColumns re-seals up to batch rows per column whose ciphertext uses a non-active key version, and returns how
// many rows were re-sealed. Each row is read, re-sealed outside the writer and written back only if it is unchanged
// (compare-and-set), so concurrent updates are never overwritten. Run it repeatedly (background job) until it
// returns 0; then the old version can be retired.
func (kr *Keyring) ResealColumns(ctx context.Context, s *store.Store, cols []Column, batch int) (int, error) {
	total := 0
	for _, c := range cols {
		if !identRE.MatchString(c.Table) || !identRE.MatchString(c.IDColumn) || !identRE.MatchString(c.BlobColumn) {
			return total, fmt.Errorf("keyring: invalid column descriptor %s.%s", c.Table, c.BlobColumn)
		}
		todo, err := kr.staleRows(ctx, s, c, batch)
		if err != nil {
			return total, err
		}
		for i := range todo {
			if todo[i].new, err = kr.Reseal(c.Purpose, c.AAD(todo[i].id), todo[i].old); err != nil {
				return total, fmt.Errorf("keyring: reseal %s.%s %s: %w", c.Table, c.BlobColumn, todo[i].id, err)
			}
		}
		if len(todo) == 0 {
			continue
		}
		err = s.W().TxNamed(ctx, "keyring.reseal", func(tx *store.Tx) error {
			for _, it := range todo {
				res, err := tx.SQL.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s = ?", //nolint:gosec // identifiers validated above
					c.Table, c.BlobColumn, c.IDColumn, c.BlobColumn), it.new, it.id, it.old)
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n == 1 {
					total++
				}
			}
			return nil
		})
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

type staleRow struct {
	id       string
	old, new []byte
}

// staleRows returns up to limit rows of c sealed with a non-active key version.
func (kr *Keyring) staleRows(ctx context.Context, s *store.Store, c Column, limit int) ([]staleRow, error) {
	rows, err := s.ReadDB().QueryContext(ctx, fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s IS NOT NULL", //nolint:gosec // identifiers validated by the caller
		c.IDColumn, c.BlobColumn, c.Table, c.BlobColumn))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []staleRow
	for rows.Next() && len(out) < limit {
		var it staleRow
		if err := rows.Scan(&it.id, &it.old); err != nil {
			return nil, err
		}
		if len(it.old) > 0 && kr.NeedsReseal(c.Purpose, it.old) {
			out = append(out, it)
		}
	}
	return out, rows.Err()
}

// VersionInUse reports whether any row of cols is still sealed with version v of purpose p.
func VersionInUse(ctx context.Context, s *store.Store, cols []Column, p Purpose, v uint32) (bool, error) {
	for _, c := range cols {
		if c.Purpose != p {
			continue
		}
		if !identRE.MatchString(c.Table) || !identRE.MatchString(c.IDColumn) || !identRE.MatchString(c.BlobColumn) {
			return false, fmt.Errorf("keyring: invalid column descriptor %s.%s", c.Table, c.BlobColumn)
		}
		inUse, err := versionInColumn(ctx, s, c, v)
		if err != nil || inUse {
			return inUse, err
		}
	}
	return false, nil
}

func versionInColumn(ctx context.Context, s *store.Store, c Column, v uint32) (bool, error) {
	rows, err := s.ReadDB().QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s IS NOT NULL", c.BlobColumn, c.Table, c.BlobColumn)) //nolint:gosec // validated
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return false, err
		}
		if got, err := SealedVersion(b); err == nil && got == v {
			return true, nil
		}
	}
	return false, rows.Err()
}
