package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Purpose separates keys by use so that a compromise or rotation of one does not affect others.
type Purpose string

// Key purposes.
const (
	PurposeField      Purpose = "field"      // sensitive columns (reasons, comments, TOTP seeds, OIDC secrets)
	PurposeCredential Purpose = "credential" // destination login private keys, CA keys, gateway host key
	PurposeRecording  Purpose = "recording"  // wraps per-segment recording DEKs
	PurposeManifest   Purpose = "manifest"   // MACs over the recording integrity chain
	PurposeToken      Purpose = "token"      // HMACs of one-time tokens, recovery codes, action tokens
)

// Purposes lists every purpose.
var Purposes = []Purpose{PurposeField, PurposeCredential, PurposeRecording, PurposeManifest, PurposeToken}

// Key states.
const (
	StateActive      = "active"
	StateDecryptOnly = "decrypt_only"
	StateRetired     = "retired"
)

const (
	sealFormat   = 0x01
	sealHeader   = 1 + 4
	dataKeySize  = 32
	canaryKey    = "keyring.canary"
	canaryPlain  = "hallpass-keyring-canary-v1"
	canaryTable  = "settings"
	canaryColumn = "value"
)

type dataKey struct {
	id      string
	purpose Purpose
	version uint32
	state   string
	raw     []byte
	aead    cipher.AEAD
}

// Keyring holds the unwrapped purpose keys of one data directory.
type Keyring struct {
	mu      sync.RWMutex
	wrapper KeyWrapper
	keys    map[Purpose]map[uint32]*dataKey
	active  map[Purpose]uint32
}

func validPurpose(p Purpose) bool { return slices.Contains(Purposes, p) }

func wrapAAD(p Purpose, version uint32) []byte {
	return []byte("hallpass/keyring/v1|" + string(p) + "|" + strconv.FormatUint(uint64(version), 10))
}

// Load unwraps the purpose keys of s with w, creating version 1 of any missing purpose and the keyring canary.
// A KEK that does not match the data directory yields ErrWrongKEK.
func Load(ctx context.Context, s *store.Store, w KeyWrapper) (*Keyring, error) {
	kr := &Keyring{wrapper: w}
	err := s.W().TxNamed(ctx, "keyring.load", func(tx *store.Tx) error {
		rows, err := tx.Q.ListKeyringKeys(ctx)
		if err != nil {
			return err
		}
		keys, active, err := unwrapAll(rows, w)
		if err != nil {
			return err
		}
		for _, p := range Purposes {
			if _, ok := active[p]; ok {
				continue
			}
			if len(keys[p]) > 0 {
				return fmt.Errorf("keyring: purpose %s has keys but none active", p)
			}
			k, err := newDataKey(p, 1)
			if err != nil {
				return err
			}
			if err := insertKey(ctx, tx, w, k); err != nil {
				return err
			}
			keys[p] = map[uint32]*dataKey{1: k}
			active[p] = 1
		}
		kr.keys, kr.active = keys, active
		return kr.checkCanary(ctx, tx)
	})
	if err != nil {
		return nil, err
	}
	return kr, nil
}

func unwrapAll(rows []db.KeyringKey, w KeyWrapper) (map[Purpose]map[uint32]*dataKey, map[Purpose]uint32, error) {
	keys := map[Purpose]map[uint32]*dataKey{}
	active := map[Purpose]uint32{}
	for _, r := range rows {
		p := Purpose(r.Purpose)
		if !validPurpose(p) {
			return nil, nil, fmt.Errorf("%w: %q", ErrBadPurpose, r.Purpose)
		}
		if r.State == StateRetired {
			continue
		}
		if r.WrapKekID != w.ID() {
			return nil, nil, fmt.Errorf("%w: keys are wrapped by KEK %s but the configured KEK is %s", ErrWrongKEK, r.WrapKekID, w.ID())
		}
		v := uint32(r.Version) //nolint:gosec // CHECK constraint keeps versions small and positive
		raw, err := w.Unwrap(r.Wrapped, wrapAAD(p, v))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: cannot unwrap %s key v%d", ErrWrongKEK, p, v)
		}
		k, err := buildKey(r.ID, p, v, r.State, raw)
		if err != nil {
			return nil, nil, err
		}
		if keys[p] == nil {
			keys[p] = map[uint32]*dataKey{}
		}
		keys[p][v] = k
		if r.State == StateActive {
			active[p] = v
		}
	}
	return keys, active, nil
}

func newDataKey(p Purpose, version uint32) (*dataKey, error) {
	raw := make([]byte, dataKeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return buildKey(ids.New(ids.Keyring), p, version, StateActive, raw)
}

func buildKey(id string, p Purpose, v uint32, state string, raw []byte) (*dataKey, error) {
	if len(raw) != dataKeySize {
		return nil, fmt.Errorf("keyring: %s key v%d has invalid length", p, v)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &dataKey{id: id, purpose: p, version: v, state: state, raw: raw, aead: aead}, nil
}

func insertKey(ctx context.Context, tx *store.Tx, w KeyWrapper, k *dataKey) error {
	wrapped, err := w.Wrap(k.raw, wrapAAD(k.purpose, k.version))
	if err != nil {
		return err
	}
	return tx.Q.InsertKeyringKey(ctx, db.InsertKeyringKeyParams{
		ID: k.id, Purpose: string(k.purpose), Version: int64(k.version), Wrapped: wrapped,
		WrapKekID: w.ID(), State: k.state, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(),
	})
}

func (kr *Keyring) checkCanary(ctx context.Context, tx *store.Tx) error {
	aad := FieldAAD(canaryTable, canaryColumn, canaryKey)
	row, err := tx.Q.GetSetting(ctx, canaryKey)
	if errors.Is(err, sql.ErrNoRows) {
		sealed, err := kr.sealLocked(PurposeField, aad, []byte(canaryPlain))
		if err != nil {
			return err
		}
		return tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: canaryKey, Value: base64.StdEncoding.EncodeToString(sealed), UpdatedAt: tx.NowMicros(),
		})
	}
	if err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(row.Value)
	if err != nil {
		return fmt.Errorf("%w: canary unreadable", ErrWrongKEK)
	}
	pt, err := kr.openLocked(PurposeField, aad, sealed)
	if err != nil || string(pt) != canaryPlain {
		return fmt.Errorf("%w: keyring canary does not verify", ErrWrongKEK)
	}
	return nil
}

func resealCanary(ctx context.Context, tx *store.Tx, from, to *dataKey) error {
	row, err := tx.Q.GetSetting(ctx, canaryKey)
	if err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(row.Value)
	if err != nil {
		return fmt.Errorf("%w: canary unreadable", ErrWrongKEK)
	}
	aad := FieldAAD(canaryTable, canaryColumn, canaryKey)
	pt, err := openWith(from, aad, sealed)
	if err != nil {
		return fmt.Errorf("%w: keyring canary does not verify", ErrWrongKEK)
	}
	resealed, err := sealWith(to, aad, pt)
	if err != nil {
		return err
	}
	return tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: canaryKey, Value: base64.StdEncoding.EncodeToString(resealed), UpdatedAt: tx.NowMicros(),
	})
}

// FieldAAD builds associated data binding a sealed value to its storage location.
func FieldAAD(table, column, rowID string) []byte {
	return []byte(table + "|" + column + "|" + rowID)
}

func sealAAD(p Purpose, version uint32, aad []byte) []byte {
	out := make([]byte, 0, 40+len(aad))
	out = append(out, "hallpass/seal/v1|"...)
	out = append(out, p...)
	out = append(out, '|')
	out = strconv.AppendUint(out, uint64(version), 10)
	out = append(out, '|')
	return append(out, aad...)
}

// Seal encrypts plaintext with the active key of purpose p, binding aad (see FieldAAD).
// Output: 0x01 | key version (u32 BE) | nonce (12) | AES-256-GCM ciphertext+tag.
func (kr *Keyring) Seal(p Purpose, aad, plaintext []byte) ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.sealLocked(p, aad, plaintext)
}

func (kr *Keyring) sealLocked(p Purpose, aad, plaintext []byte) ([]byte, error) {
	if kr.keys == nil {
		return nil, ErrNotUnlocked
	}
	v, ok := kr.active[p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadPurpose, p)
	}
	return sealWith(kr.keys[p][v], aad, plaintext)
}

func sealWith(k *dataKey, aad, plaintext []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	out := make([]byte, sealHeader+ns, sealHeader+ns+len(plaintext)+k.aead.Overhead())
	out[0] = sealFormat
	binary.BigEndian.PutUint32(out[1:5], k.version)
	if _, err := rand.Read(out[sealHeader:]); err != nil {
		return nil, err
	}
	return k.aead.Seal(out, out[sealHeader:], plaintext, sealAAD(k.purpose, k.version, aad)), nil //nolint:gosec // G407 false positive: nonce filled by crypto/rand above
}

// Open decrypts a value produced by Seal with the same purpose and aad.
func (kr *Keyring) Open(p Purpose, aad, sealed []byte) ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.openLocked(p, aad, sealed)
}

func (kr *Keyring) openLocked(p Purpose, aad, sealed []byte) ([]byte, error) {
	if kr.keys == nil {
		return nil, ErrNotUnlocked
	}
	v, err := SealedVersion(sealed)
	if err != nil {
		return nil, err
	}
	k, ok := kr.keys[p][v]
	if !ok {
		return nil, fmt.Errorf("%w: %s v%d", ErrUnknownKey, p, v)
	}
	return openWith(k, aad, sealed)
}

func openWith(k *dataKey, aad, sealed []byte) ([]byte, error) {
	v, err := SealedVersion(sealed)
	if err != nil {
		return nil, err
	}
	if v != k.version {
		return nil, fmt.Errorf("%w: %s v%d", ErrUnknownKey, k.purpose, v)
	}
	ns := k.aead.NonceSize()
	if len(sealed) < sealHeader+ns+k.aead.Overhead() {
		return nil, ErrBadSealed
	}
	pt, err := k.aead.Open(nil, sealed[sealHeader:sealHeader+ns], sealed[sealHeader+ns:], sealAAD(k.purpose, v, aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// SealedVersion returns the key version recorded in a sealed value.
func SealedVersion(sealed []byte) (uint32, error) {
	if len(sealed) < sealHeader || sealed[0] != sealFormat {
		return 0, ErrBadSealed
	}
	return binary.BigEndian.Uint32(sealed[1:5]), nil
}

// NeedsReseal reports whether sealed was produced with a key other than the active one for p.
func (kr *Keyring) NeedsReseal(p Purpose, sealed []byte) bool {
	v, err := SealedVersion(sealed)
	if err != nil {
		return false
	}
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return v != kr.active[p]
}

// Reseal re-encrypts sealed under the active key (used by background rotation jobs).
func (kr *Keyring) Reseal(p Purpose, aad, sealed []byte) ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	pt, err := kr.openLocked(p, aad, sealed)
	if err != nil {
		return nil, err
	}
	return kr.sealLocked(p, aad, pt)
}

// MAC computes HMAC-SHA-256 of data under the active key of purpose p (for token and manifest digests).
func (kr *Keyring) MAC(p Purpose, data []byte) ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.keys == nil {
		return nil, ErrNotUnlocked
	}
	v, ok := kr.active[p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadPurpose, p)
	}
	return mac(kr.keys[p][v], data), nil
}

// MACAll returns the MAC of data under every non-retired key of purpose p, active first. Lookups by MAC use it
// so that values created before a rotation still match.
func (kr *Keyring) MACAll(p Purpose, data []byte) ([][]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.keys == nil {
		return nil, ErrNotUnlocked
	}
	versions := make([]uint32, 0, len(kr.keys[p]))
	for v := range kr.keys[p] {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	out := make([][]byte, 0, len(versions))
	for _, v := range versions {
		out = append(out, mac(kr.keys[p][v], data))
	}
	return out, nil
}

func mac(k *dataKey, data []byte) []byte {
	h := hmac.New(sha256.New, k.raw)
	h.Write([]byte("hallpass/mac/v1|" + string(k.purpose) + "|"))
	h.Write(data)
	return h.Sum(nil)
}

// VerifyMAC reports whether m equals the MAC of data under any non-retired key of p (constant time per key).
func (kr *Keyring) VerifyMAC(p Purpose, data, m []byte) bool {
	all, err := kr.MACAll(p, data)
	if err != nil {
		return false
	}
	ok := false
	for _, c := range all {
		if hmac.Equal(c, m) {
			ok = true
		}
	}
	return ok
}

// KEKID returns the identifier of the KEK wrapping this keyring.
func (kr *Keyring) KEKID() string { return kr.wrapper.ID() }

// PurposeStatus describes the keys of one purpose.
type PurposeStatus struct {
	Purpose       Purpose  `json:"purpose"`
	ActiveVersion uint32   `json:"active_version"`
	Versions      []uint32 `json:"versions"`
}

// Status reports the loaded keys (no secrets).
func (kr *Keyring) Status() []PurposeStatus {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make([]PurposeStatus, 0, len(Purposes))
	for _, p := range Purposes {
		st := PurposeStatus{Purpose: p, ActiveVersion: kr.active[p]}
		for v := range kr.keys[p] {
			st.Versions = append(st.Versions, v)
		}
		slices.Sort(st.Versions)
		out = append(out, st)
	}
	return out
}

// Rotate creates a new active version for purpose p; the previous version becomes decrypt-only.
func (kr *Keyring) Rotate(ctx context.Context, s *store.Store, p Purpose) (uint32, error) {
	if !validPurpose(p) {
		return 0, fmt.Errorf("%w: %q", ErrBadPurpose, p)
	}
	kr.mu.RLock()
	cur := kr.active[p]
	prev := kr.keys[p][cur]
	kr.mu.RUnlock()
	next, err := newDataKey(p, cur+1)
	if err != nil {
		return 0, err
	}
	err = s.W().TxNamed(ctx, "keyring.rotate", func(tx *store.Tx) error {
		n, err := tx.Q.UpdateKeyringKeyState(ctx, db.UpdateKeyringKeyStateParams{State: StateDecryptOnly, UpdatedAt: tx.NowMicros(), ID: prev.id})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: active %s key changed concurrently", store.ErrConflict, p)
		}
		if err := insertKey(ctx, tx, kr.wrapper, next); err != nil {
			return err
		}
		if p == PurposeField {
			// The canary must always be sealed with the active field key so retiring old versions never orphans it.
			if err := resealCanary(ctx, tx, prev, next); err != nil {
				return err
			}
		}
		tx.AfterCommit(func() {
			kr.mu.Lock()
			prev.state = StateDecryptOnly
			kr.keys[p][next.version] = next
			kr.active[p] = next.version
			kr.mu.Unlock()
		})
		return nil
	})
	if err != nil {
		return 0, err
	}
	return next.version, nil
}

// Retire marks a decrypt-only version as retired once nothing references it. Retired keys are not loaded.
func (kr *Keyring) Retire(ctx context.Context, s *store.Store, p Purpose, version uint32) error {
	kr.mu.RLock()
	k, ok := kr.keys[p][version]
	kr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s v%d", ErrUnknownKey, p, version)
	}
	if k.state != StateDecryptOnly {
		return fmt.Errorf("only decrypt-only keys can be retired (%s v%d is %s)", p, version, k.state)
	}
	return s.W().TxNamed(ctx, "keyring.retire", func(tx *store.Tx) error {
		if _, err := tx.Q.UpdateKeyringKeyState(ctx, db.UpdateKeyringKeyStateParams{State: StateRetired, UpdatedAt: tx.NowMicros(), ID: k.id}); err != nil {
			return err
		}
		tx.AfterCommit(func() {
			kr.mu.Lock()
			delete(kr.keys[p], version)
			kr.mu.Unlock()
		})
		return nil
	})
}

// RotateKEK rewraps every non-retired purpose key from oldW to newW in one transaction (offline operation; the
// caller holds the data-directory lock). After success only newW can load the keyring.
func RotateKEK(ctx context.Context, s *store.Store, oldW, newW KeyWrapper) (int, error) {
	if oldW.ID() == newW.ID() {
		return 0, errors.New("new KEK is identical to the current KEK")
	}
	count := 0
	err := s.W().TxNamed(ctx, "keyring.rotate_kek", func(tx *store.Tx) error {
		count = 0
		rows, err := tx.Q.ListKeyringKeys(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State == StateRetired {
				continue
			}
			if r.WrapKekID != oldW.ID() {
				return fmt.Errorf("%w: key %s wrapped by %s, expected %s", ErrWrongKEK, r.ID, r.WrapKekID, oldW.ID())
			}
			aad := wrapAAD(Purpose(r.Purpose), uint32(r.Version)) //nolint:gosec // small positive version
			raw, err := oldW.Unwrap(r.Wrapped, aad)
			if err != nil {
				return fmt.Errorf("%w: unwrap %s", ErrWrongKEK, r.ID)
			}
			wrapped, err := newW.Wrap(raw, aad)
			if err != nil {
				return err
			}
			if _, err := tx.Q.UpdateKeyringKeyWrap(ctx, db.UpdateKeyringKeyWrapParams{Wrapped: wrapped, WrapKekID: newW.ID(), UpdatedAt: tx.NowMicros(), ID: r.ID}); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if _, err := Load(ctx, s, newW); err != nil {
		return count, fmt.Errorf("verification after KEK rotation failed: %w", err)
	}
	return count, nil
}
