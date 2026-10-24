package keyring

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func newKEK(t *testing.T) *LocalKEK {
	t.Helper()
	k, err := GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewLocalKEK(k)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func loadRing(t *testing.T) (*Keyring, *LocalKEK, *store.Store) {
	t.Helper()
	s := storetest.Open(t)
	w := newKEK(t)
	kr, err := Load(context.Background(), s, w)
	if err != nil {
		t.Fatal(err)
	}
	return kr, w, s
}

func TestSealOpenRoundTrip(t *testing.T) {
	kr, _, _ := loadRing(t)
	aad := FieldAAD("access_requests", "reason_enc", "req_1")
	for _, p := range Purposes {
		sealed, err := kr.Seal(p, aad, []byte("secret reason"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, []byte("secret reason")) {
			t.Fatal("plaintext visible in sealed value")
		}
		pt, err := kr.Open(p, aad, sealed)
		if err != nil || string(pt) != "secret reason" {
			t.Fatalf("%s: %q %v", p, pt, err)
		}
	}
}

// HP-CRY-003: AAD binds sealed values to their table/column/row; tampering and key confusion fail.
func TestSealBindsContext(t *testing.T) {
	kr, _, _ := loadRing(t)
	aad := FieldAAD("t", "c", "row1")
	sealed, err := kr.Seal(PurposeField, aad, []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open(PurposeField, FieldAAD("t", "c", "row2"), sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("row swap not detected: %v", err)
	}
	if _, err := kr.Open(PurposeCredential, aad, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("purpose confusion not detected: %v", err)
	}
	for i := range sealed {
		mod := bytes.Clone(sealed)
		mod[i] ^= 0x01
		if _, err := kr.Open(PurposeField, aad, mod); err == nil {
			t.Fatalf("bit flip at %d not detected", i)
		}
	}
	if _, err := kr.Open(PurposeField, aad, sealed[:10]); err == nil {
		t.Fatal("truncated value accepted")
	}
}

func TestNonceUniqueness(t *testing.T) {
	kr, _, _ := loadRing(t)
	seen := map[string]bool{}
	for range 10000 {
		s, err := kr.Seal(PurposeField, nil, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		n := string(s[sealHeader : sealHeader+12])
		if seen[n] {
			t.Fatal("nonce reused")
		}
		seen[n] = true
	}
}

// HP-CRY-001: a different KEK cannot open the keyring.
func TestWrongKEKRejected(t *testing.T) {
	_, _, s := loadRing(t)
	if _, err := Load(context.Background(), s, newKEK(t)); !errors.Is(err, ErrWrongKEK) {
		t.Fatalf("expected ErrWrongKEK, got %v", err)
	}
}

func TestReloadSameKEK(t *testing.T) {
	kr, w, s := loadRing(t)
	sealed, _ := kr.Seal(PurposeField, nil, []byte("persisted"))
	kr2, err := Load(context.Background(), s, w)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := kr2.Open(PurposeField, nil, sealed); err != nil || string(pt) != "persisted" {
		t.Fatalf("%q %v", pt, err)
	}
}

// HP-CRY-002: purpose-key rotation keeps old data readable, seals new data with the new key, and reseals.
func TestPurposeRotation(t *testing.T) {
	kr, w, s := loadRing(t)
	ctx := context.Background()
	aad := FieldAAD("t", "c", "r")
	old, _ := kr.Seal(PurposeField, aad, []byte("old"))
	v, err := kr.Rotate(ctx, s, PurposeField)
	if err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	if pt, err := kr.Open(PurposeField, aad, old); err != nil || string(pt) != "old" {
		t.Fatalf("old data unreadable after rotation: %v", err)
	}
	fresh, _ := kr.Seal(PurposeField, aad, []byte("new"))
	if ver, _ := SealedVersion(fresh); ver != 2 {
		t.Fatalf("new seal uses v%d", ver)
	}
	if !kr.NeedsReseal(PurposeField, old) || kr.NeedsReseal(PurposeField, fresh) {
		t.Fatal("NeedsReseal wrong")
	}
	resealed, err := kr.Reseal(PurposeField, aad, old)
	if err != nil {
		t.Fatal(err)
	}
	if ver, _ := SealedVersion(resealed); ver != 2 {
		t.Fatal("reseal did not use active key")
	}
	// Persisted state matches after reload.
	kr2, err := Load(ctx, s, w)
	if err != nil {
		t.Fatal(err)
	}
	if st := kr2.Status(); st[0].Purpose != PurposeField || st[0].ActiveVersion != 2 || len(st[0].Versions) != 2 {
		t.Fatalf("status after reload: %+v", st[0])
	}
	if err := kr.Retire(ctx, s, PurposeField, 2); err == nil {
		t.Fatal("retiring the active key must fail")
	}
	if err := kr.Retire(ctx, s, PurposeField, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open(PurposeField, aad, old); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("retired key still usable: %v", err)
	}
	kr3, err := Load(ctx, s, w)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := kr3.Open(PurposeField, aad, resealed); err != nil || string(pt) != "old" {
		t.Fatalf("resealed unreadable after retire+reload: %v", err)
	}
}

// HP-CRY-002: KEK rotation rewraps purpose keys; only the new KEK opens the keyring afterwards.
func TestKEKRotation(t *testing.T) {
	kr, oldW, s := loadRing(t)
	ctx := context.Background()
	sealed, _ := kr.Seal(PurposeCredential, nil, []byte("private key"))
	newW := newKEK(t)
	n, err := RotateKEK(ctx, s, oldW, newW)
	if err != nil || n != len(Purposes) {
		t.Fatalf("rotated %d: %v", n, err)
	}
	if _, err := Load(ctx, s, oldW); !errors.Is(err, ErrWrongKEK) {
		t.Fatalf("old KEK still works: %v", err)
	}
	kr2, err := Load(ctx, s, newW)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := kr2.Open(PurposeCredential, nil, sealed); err != nil || string(pt) != "private key" {
		t.Fatalf("data unreadable after KEK rotation: %v", err)
	}
	if _, err := RotateKEK(ctx, s, newW, newW); err == nil {
		t.Fatal("rotating to the same KEK must fail")
	}
}

func TestMACs(t *testing.T) {
	kr, _, s := loadRing(t)
	m1, err := kr.MAC(PurposeToken, []byte("tok"))
	if err != nil || len(m1) != 32 {
		t.Fatal(err)
	}
	if !kr.VerifyMAC(PurposeToken, []byte("tok"), m1) || kr.VerifyMAC(PurposeToken, []byte("other"), m1) {
		t.Fatal("verify wrong")
	}
	m2, _ := kr.MAC(PurposeManifest, []byte("tok"))
	if bytes.Equal(m1, m2) {
		t.Fatal("purposes share MAC keys")
	}
	if _, err := kr.Rotate(context.Background(), s, PurposeToken); err != nil {
		t.Fatal(err)
	}
	if !kr.VerifyMAC(PurposeToken, []byte("tok"), m1) {
		t.Fatal("pre-rotation MAC no longer verifies")
	}
	all, _ := kr.MACAll(PurposeToken, []byte("tok"))
	if len(all) != 2 || !bytes.Equal(all[1], m1) {
		t.Fatal("MACAll ordering wrong")
	}
}

func TestParseKEK(t *testing.T) {
	k, _ := GenerateKEK()
	for _, data := range [][]byte{EncodeKEK(k), []byte(" " + string(EncodeKEK(k)) + "\n\n"), k} {
		got, err := ParseKEK(data)
		if err != nil || !bytes.Equal(got, k) {
			t.Fatalf("parse %q: %v", data, err)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 100)} {
		if _, err := ParseKEK([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := NewLocalKEK(make([]byte, 32)); err == nil {
		t.Fatal("all-zero KEK accepted")
	}
}

// HP-CRY-001, HP-DB-010: KEK provisioning rules.
func TestLoadKEKSources(t *testing.T) {
	dir := t.TempDir()
	k, _ := GenerateKEK()
	path := filepath.Join(dir, "kek")
	if err := WriteKEKFile(path, k); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o400 {
		t.Fatalf("KEK file mode %v", fi.Mode().Perm())
	}
	if err := WriteKEKFile(path, k); err == nil {
		t.Fatal("WriteKEKFile overwrote an existing file")
	}
	w, err := LoadKEK(Source{Kind: "file", File: path, Production: true})
	if err != nil || w.ID() != KEKID(k) {
		t.Fatalf("load file: %v", err)
	}
	if _, err := LoadKEK(Source{Kind: "file", File: "", Production: true}); !errors.Is(err, ErrNoKEK) {
		t.Fatalf("production without KEK: %v", err)
	}
	if _, err := LoadKEK(Source{Kind: "file", File: filepath.Join(dir, "missing"), Production: true}); !errors.Is(err, ErrNoKEK) {
		t.Fatalf("missing file: %v", err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, EncodeKEK(k), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKEK(Source{Kind: "file", File: loose, Production: true}); !errors.Is(err, ErrBadKEKFile) {
		t.Fatalf("world-readable KEK accepted: %v", err)
	}
	env := []string{"HALLPASS_KEK=" + strings.TrimSpace(string(EncodeKEK(k)))}
	if w, err := LoadKEK(Source{Kind: "env", Environ: env}); err != nil || w.ID() != KEKID(k) {
		t.Fatalf("env: %v", err)
	}
	if _, err := LoadKEK(Source{Kind: "env"}); !errors.Is(err, ErrNoKEK) {
		t.Fatalf("env missing: %v", err)
	}
	data := filepath.Join(dir, "data")
	w1, err := LoadKEK(Source{Kind: "file", DataDir: data})
	if err != nil {
		t.Fatalf("dev KEK: %v", err)
	}
	w2, err := LoadKEK(Source{Kind: "file", DataDir: data})
	if err != nil || w1.ID() != w2.ID() {
		t.Fatalf("dev KEK not stable: %v", err)
	}
}

// SR-18 (HP-CRY-002): KEK rotation also rewraps retired keys, so no keyring row stays under the old KEK and backups
// (which refuse a keyring wrapped under several KEKs) keep working. A retired row left under an even older KEK by an
// earlier binary is skipped instead of failing the rotation.
func TestKEKRotationRewrapsRetiredKeys(t *testing.T) {
	kr, w1, s := loadRing(t)
	ctx := context.Background()
	if _, err := kr.Rotate(ctx, s, PurposeToken); err != nil {
		t.Fatal(err)
	}
	if err := kr.Retire(ctx, s, PurposeToken, 1); err != nil {
		t.Fatal(err)
	}
	if v := kr.ActiveVersion(PurposeToken); v != 2 {
		t.Fatalf("active token version %d", v)
	}
	kekOf := func() map[string]int {
		out := map[string]int{}
		rows, err := s.ReadDB().QueryContext(ctx, "SELECT wrap_kek_id FROM keyring_keys")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out[id]++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	w2 := newKEK(t)
	n, err := RotateKEK(ctx, s, w1, w2)
	if err != nil || n != len(Purposes)+1 {
		t.Fatalf("rotated %d: %v", n, err)
	}
	if got := kekOf(); len(got) != 1 || got[w2.ID()] != len(Purposes)+1 {
		t.Fatalf("keys by KEK after rotation: %v", got)
	}
	// Simulate a retired row left under w1 by an older binary: the next rotation skips it.
	if err := s.W().Exec(ctx, "UPDATE keyring_keys SET wrap_kek_id = ? WHERE state = 'retired'", w1.ID()); err != nil {
		t.Fatal(err)
	}
	w3 := newKEK(t)
	if n, err := RotateKEK(ctx, s, w2, w3); err != nil || n != len(Purposes) {
		t.Fatalf("rotation with a stale retired row: %d %v", n, err)
	}
}
