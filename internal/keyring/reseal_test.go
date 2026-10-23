package keyring_test

import (
	"context"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

// HP-CRY-002: after rotation, background re-encryption moves sealed fields to the active version.
func TestResealColumns(t *testing.T) {
	ctx := context.Background()
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	// A scratch table with a BLOB column stands in for a sealed column.
	if err := s.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(ctx, `CREATE TABLE reseal_test (id TEXT PRIMARY KEY, blob BLOB)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	col := keyring.FieldColumn("reseal_test", "id", "blob", keyring.PurposeField)
	for _, id := range []string{"a", "b", "c"} {
		sealed, err := kr.Seal(keyring.PurposeField, col.AAD(id), []byte("secret-"+id))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.W().Tx(ctx, func(tx *store.Tx) error {
			_, err := tx.SQL.ExecContext(ctx, `INSERT INTO reseal_test VALUES (?, ?)`, id, sealed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := kr.ResealColumns(ctx, s, []keyring.Column{col}, 10); err != nil || n != 0 {
		t.Fatalf("nothing to do expected: %d %v", n, err)
	}
	v2, err := kr.Rotate(ctx, s, keyring.PurposeField)
	if err != nil {
		t.Fatal(err)
	}
	// Before re-encryption the old version still protects data; other purposes and versions are unaffected.
	if inUse, err := keyring.VersionInUse(ctx, s, []keyring.Column{col}, keyring.PurposeField, v2-1); err != nil || !inUse {
		t.Fatalf("v%d in use: %v %v", v2-1, inUse, err)
	}
	if inUse, err := keyring.VersionInUse(ctx, s, []keyring.Column{col}, keyring.PurposeCredential, v2-1); err != nil || inUse {
		t.Fatalf("other purpose reported in use: %v %v", inUse, err)
	}
	if _, err := keyring.VersionInUse(ctx, s, []keyring.Column{{Table: "x; DROP", IDColumn: "id", BlobColumn: "b", Purpose: keyring.PurposeField}},
		keyring.PurposeField, 1); err == nil {
		t.Fatal("invalid identifier accepted by VersionInUse")
	}
	n, err := kr.ResealColumns(ctx, s, []keyring.Column{col}, 2)
	if err != nil || n != 2 {
		t.Fatalf("first batch %d %v", n, err)
	}
	n, err = kr.ResealColumns(ctx, s, []keyring.Column{col}, 2)
	if err != nil || n != 1 {
		t.Fatalf("second batch %d %v", n, err)
	}
	rows, err := s.ReadDB().QueryContext(ctx, `SELECT id, blob FROM reseal_test`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			t.Fatal(err)
		}
		if v, _ := keyring.SealedVersion(blob); v != v2 {
			t.Fatalf("%s still on v%d", id, v)
		}
		pt, err := kr.Open(keyring.PurposeField, col.AAD(id), blob)
		if err != nil || string(pt) != "secret-"+id {
			t.Fatalf("%s: %q %v", id, pt, err)
		}
	}
	if inUse, err := keyring.VersionInUse(ctx, s, []keyring.Column{col}, keyring.PurposeField, v2-1); err != nil || inUse {
		t.Fatalf("v%d still in use after re-encryption: %v %v", v2-1, inUse, err)
	}
	if kr.KEKID() == "" {
		t.Fatal("empty KEK id")
	}
	if _, err := kr.ResealColumns(ctx, s, []keyring.Column{{Table: "x; DROP", IDColumn: "id", BlobColumn: "b"}}, 1); err == nil {
		t.Fatal("invalid identifier accepted")
	}
}
