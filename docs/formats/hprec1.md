# HPREC1 — Hallpass encrypted recording segment format

Status: **implemented and tested** (`internal/recording/hprec`). **Not externally reviewed. Needs external cryptographic
review before 1.0 (DECISIONS.md R-02, release gate RG-9).**

Normative sources: GOAL.md HP-CRY-004/005 and HP-REC-001..004/009, PLAN.md §13.3–13.7, ADR-0005. This document is
the byte-level specification. Where it refines PLAN §13.3, the refinement is listed in [§12](#12-refinements-of-plan-133).
The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Overview

A segment holds the recorded events of one SSH channel for a bounded period. It is one file:

```
offset  size        field
0       8           magic = "HPREC1\n\0"   (48 50 52 45 43 31 0a 00)
8       4           header_len (u32 big-endian), 1..4096
12      header_len  header: canonical JSON (§3)
12+N    256         key slot A (§4)
268+N   256         key slot B (§4)
524+N   ...         frames (§6), until end of file
```

All integers in fixed-width fields are big-endian. `N` = `header_len`. `uvarint` is the unsigned LEB128 encoding
used by Go's `encoding/binary` (7 bits per byte, least significant group first, high bit = continuation), and `varint`
is zigzag (`(n << 1) ^ (n >> 63)`) followed by `uvarint`. Readers MUST reject non-minimal varint encodings (an
encoding longer than one byte whose last byte is `0x00`) and encodings that overflow 64 bits.

Primitives (no others are used):

| Use | Primitive |
| --- | --- |
| Header hash, ciphertext hash, plaintext hash, slot checksum | SHA-256 |
| Payload key derivation | HKDF-SHA256 (RFC 5869) |
| Frame encryption | ChaCha20-Poly1305 (RFC 8439), 32-byte key, 12-byte nonce, 16-byte tag |
| DEK wrapping | caller-supplied AEAD via `DEKWrapper` (production: keyring recording purpose key, AES-256-GCM) |
| Randomness | `crypto/rand` |

## 2. Header hash

```
H = SHA-256( magic || header_len (4 bytes, BE) || header )
```

`H` is stored in SQLite (`recording_segments.header_sha256`). It is the associated data of every frame and part of the
DEK-wrapping AAD, so the header is authenticated even though it is plaintext.

## 3. Header

The header is a JSON object with exactly these keys, emitted in this (byte-wise sorted) order, with no insignificant
whitespace, as the Go `encoding/json` encoder produces for the values below:

| Key | Type | Value |
| --- | --- | --- |
| `aead` | string | `"chacha20poly1305-stream"` |
| `channel_id` | string | 1–128 characters of `[A-Za-z0-9_.:-]` |
| `created_at` | string | UTC, layout `YYYY-MM-DDTHH:MM:SS.ffffffZ` (exactly 6 fractional digits), year 1970–9999 |
| `frame_max` | integer | `65536` |
| `kind` | string | `"pty"` or `"exec"` |
| `ordinal` | integer | 0..2³²−1, position of the segment within its channel |
| `payload_salt` | string | 16 random bytes, standard base64 with padding (24 characters) |
| `prev_segment_sha256` | string | `""` when `ordinal` = 0; otherwise 64 lowercase hex characters (§3.1) |
| `segment_id` | string | 1–128 characters of `[A-Za-z0-9_.:-]` |
| `session_id` | string | 1–128 characters of `[A-Za-z0-9_.:-]` |
| `v` | integer | `1` |

Because every string is restricted to characters that JSON never escapes, the canonical encoding is unique. Readers MUST
parse the header, validate every field, re-encode it canonically and reject the file unless the result is byte-identical
to the stored header (this rejects whitespace, reordering, duplicate or unknown keys, alternate escapes and
case-variant keys). Example (line-wrapped here only):

```
{"aead":"chacha20poly1305-stream","channel_id":"chn_01jabcdefghjkmnpqrstvwxyz0","created_at":"2026-10-23T12:00:00.123456Z",
"frame_max":65536,"kind":"pty","ordinal":0,"payload_salt":"AQIDAAAAAAAAAAAAAAAAAA==","prev_segment_sha256":"",
"segment_id":"seg_01jabcdefghjkmnpqrstvwxyz0","session_id":"ses_01jabcdefghjkmnpqrstvwxyz0","v":1}
```

A reader that finds `v` ≠ 1, a different `aead`, or a different `frame_max` MUST report an unsupported version, not
attempt to decode.

### 3.1 Segment chaining

`prev_segment_sha256` is the `ciphertext_sha256` (§8) of the previous segment (`ordinal − 1`) of the same channel,
known because rollover finalizes the previous segment before creating the next. Together with `ordinal` and `H` stored
in SQLite, it lets verification detect a missing, reordered or substituted segment in a channel.

## 4. Key slots

Two fixed 256-byte slots follow the header. They are **not** covered by `H`, so the DEK can be rewrapped in place
(§9). Layout of one slot:

```
offset  size  field
0       4     slot magic "HPK1"
4       4     gen (u32 BE), >= 1
8       1     k = key_id length, 1..64
9       k     key_id: printable ASCII 0x21..0x7e
9+k     2     w = wrapped length (u16 BE), >= 1, 9+k+2+w <= 224
11+k    w     wrapped DEK (opaque bytes produced by DEKWrapper.Wrap)
11+k+w  ...   zero bytes up to offset 224 (MUST be zero)
224     32    SHA-256(slot bytes 0..223)
```

An all-zero slot is *empty* (never written). The checksum detects torn or partially written slots. It is **not** a MAC:
anyone can recompute it. The authenticity of the DEK comes only from the wrapper's AEAD and its associated data:

```
dek_aad = "hallpass/rec/dek/v1|" || segment_id || "|" || lowercase_hex(H)
```

`DEKWrapper.Unwrap(key_id, wrapped, dek_aad)` MUST fail unless the wrapped value was produced for exactly this AAD under
the identified key, and MUST return exactly 32 bytes. With the keyring implementation, `wrapped` is the keyring's
sealed-value format (`0x01 | key_version | nonce | AES-256-GCM ciphertext+tag`) and `key_id` names the recording
purpose-key version.

**Slot selection.** A reader decodes both slots, orders the decodable ones by `gen` descending (slot A first on a tie),
and uses the first one that unwraps. If none unwraps the file is unreadable with the available keys (`ErrNoKey`). `gen`
and `key_id` are not authenticated: changing them can at most make a reader try another slot or fail, never yield a
different DEK.

At creation slot A holds `gen` 1 and slot B is empty.

## 5. Keys

```
DEK = 32 bytes from crypto/rand, fresh per segment
K   = HKDF-SHA256(IKM = DEK, salt = payload_salt (16 bytes), info = "hallpass/rec/payload/v1", L = 32)
```

`K` is the ChaCha20-Poly1305 key for every frame of the segment. Neither `DEK` nor `K` is ever written unencrypted.

## 6. Frames

Frames follow slot B back to back until end of file:

```
ct_len  u32 BE   17 .. 65552  (= plaintext length 1..65536 + 16-byte tag)
ct      ct_len bytes
```

Frame `i` (0-based, counting from the first frame) is sealed as

```
nonce_i = BE88(i) || flag          11-byte big-endian counter, 1 flag byte
flag    = 0x01 for the final frame, 0x00 for every other frame
ct_i    = ChaCha20-Poly1305.Seal(K, nonce_i, plaintext_i, ad = H)
```

This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, 2015), as used by age. Rules:

1. Plaintext length is 1..`frame_max` (65536). Frames are never empty.
2. Exactly one frame, the last one in the file, has flag 0x01. No bytes follow it.
3. A frame's plaintext is a concatenation of whole records (§7). Records never span frames.
4. The final frame's plaintext ends with exactly one `segment.footer` record, and no other frame contains one.

The flag is not stored. A reader opens frame `i` with flag 0x00 and, if that fails, with flag 0x01. A frame that opens
with neither is a failure. A frame that opened with flag 0x01 is final: the reader validates the footer and then requires
end of file.

## 7. Records

### 7.1 Encoding

```
type     u8        record type (§7.3)
seq      uvarint   per-access-session sequence number
t_us     varint    UTC microseconds since the Unix epoch, as a delta from the previous record in the same frame;
                   the first record of each frame is a delta from created_at (in microseconds)
mono_ns  uvarint   nanoseconds since the channel opened, <= 2^63-1
stream   u8        0 pty, 1 stdout, 2 stderr, 3 stdin, 4 meta
len      uvarint   payload length, <= 65472
payload  len bytes
```

The decoded time MUST lie in [1970-01-01T00:00:00Z, 9999-12-31T23:59:59.999999Z]. Deltas may be negative (the wall
clock can step back). Because the time base resets to `created_at` at every frame, each frame decodes independently of
the others.

### 7.2 Sequence rules

For every non-footer record `seq` >= 1, and `seq` strictly increases across the whole segment (gaps are allowed: the
sequencer is per access session and interleaves channels, HP-REC-002).

The footer record MUST have `seq` = 0, `t_us` delta = 0, `mono_ns` = 0 and `stream` = 4.

### 7.3 Record types and payloads

Strings and byte strings inside structured payloads are `uvarint length || bytes`. Integers are minimal uvarints.
Every parser MUST reject trailing bytes. The versioned event name of each type is `<name>@1` (HP-REC-001).

| Code | Name | Default stream | Payload |
| --- | --- | --- | --- |
| 1 | `exec.requested` | meta | raw exec command bytes |
| 2 | `pty.requested` | meta | cols, rows, width_px, height_px (uvarint ≤ 2³²−1 each), term (string ≤ 256), modes (bytes ≤ 4096, raw SSH terminal modes) |
| 3 | `env.accepted` | meta | name (string 1..256), value (string) |
| 4 | `terminal.output` | pty | raw bytes |
| 5 | `terminal.input` | stdin | raw bytes |
| 6 | `terminal.resized` | meta | cols, rows, width_px, height_px (uvarint ≤ 2³²−1 each) |
| 7 | `stdout` | stdout | raw bytes |
| 8 | `stderr` | stderr | raw bytes |
| 9 | `signal` | meta | SSH signal name without "SIG" (e.g. `INT`), 1..32 printable ASCII bytes, no length prefix |
| 10 | `eof` | the direction | empty |
| 11 | `exit` | meta | kind u8: 0 → status (uvarint ≤ 2³²−1); 1 → signal (string 1..32 printable), core_dumped u8 (0/1), message (string ≤ 4096) |
| 12 | `gateway.notice` | meta | code (string 1..64 of `[a-z0-9_.-]`), message (string) |
| 13 | `segment.footer` | meta | §7.4 |

Type 0 and codes above 13 are invalid in v1 and make the frame corrupt. Readers do not skip unknown types (see §11).

### 7.4 Footer

```
records           uvarint   number of non-footer records in the segment
first_seq         uvarint   seq of the first record (0 iff records = 0)
last_seq          uvarint   seq of the last record  (0 iff records = 0)
end_reason        string    1..64 characters of [a-z0-9_.-]
plaintext_sha256  32 bytes  SHA-256 over the concatenated plaintexts of all frames, excluding the footer record's
                            own encoding at the end of the final frame
```

With records > 0: `first_seq` >= 1, `last_seq` >= `first_seq` and `last_seq − first_seq` >= `records − 1`. A reader
MUST check `records`, `first_seq`, `last_seq` and `plaintext_sha256` against what it decoded. If the pending records
and the footer do not fit in one frame, the writer seals the pending records as a non-final frame and writes a final
frame containing only the footer.

## 8. Ciphertext hash and manifest

```
ciphertext_sha256 = SHA-256( every byte from the first frame's ct_len to the end of the last valid frame )
```

It covers the frames region only. The header is covered by `H`, and the slots are excluded because rewrapping changes
them. At finalization the writer returns the manifest
`{segment_id, path, header_sha256 = H, ciphertext_sha256, frames, bytes (file size), records, first_seq, last_seq,
end_reason}`. The database layer stores it and appends it to the per-session integrity chain (PLAN §13.5 step 4).
That chain is outside this format.

## 9. Write, commit and maintenance protocol

1. **Prepare** (`hprec.Prepare`): validate the header, draw the DEK and `payload_salt`, compute `H`, wrap the DEK into
   slot A. No I/O. The caller registers the `open` segment row (`H`, key ID, wrapped DEK) in the database.
2. **Create** (`Prepared.Create`): `open(path + ".partial", O_WRONLY|O_CREAT|O_EXCL, 0600)`, write magic, header and
   both slots, `fsync(file)`, `fsync(dir)`. Only after this returns is the recording *established* (HP-REC-007). On
   failure the partial file is removed and the error returned. The final path must not exist.
3. **Append / Flush**: `Append` buffers records into the current frame and, when the next record does not fit, seals and
   writes the pending frame (non-final, not yet fsynced). `Flush` seals pending records as a non-final frame and fsyncs.
   The caller decides when to flush (group commit ≤ 250 ms, or per frame in strict mode). Any write or fsync error is
   returned and permanently fails the writer. Nothing is retried, and the caller terminates the channel in mandatory
   mode (PLAN §13.5 step 3).
4. **Finalize**: seal the final frame (flag 0x01, ending with the footer), `fsync(file)`, `close`,
   `rename(.partial → final)`, `fsync(dir)`. The caller then commits the manifest. Only after that commit is the
   recording *durable and complete*.
5. **Rewrap** (`RewrapSlot`, PLAN §13.4): unwrap with the current key, wrap with the new key, and write the *other*
   slot (not the one in use) as one full 256-byte block with `gen` = highest gen + 1, then fsync. Afterwards the caller
   updates the database copy. A torn slot write fails its checksum, so readers fall back to the previous slot. Writers
   never touch the slots after Create, so rewrapping an open segment is safe.
6. **Repair** (`RepairSlot`): if no slot unwraps but the database copy of the wrapped DEK does (under this segment's
   AAD), write it into a slot that does not unwrap, with `gen` = highest gen + 1. A slot that does unwrap MUST yield the
   same DEK, or the file is reported corrupt.

## 10. Reading, verification and recovery

**Reading.** A reader parses the prefix, checks caller expectations (segment, session and channel IDs, `H` from the
database: a swapped file is internally consistent, so these checks are what detects it), selects a slot, derives `K`,
then processes frames one at a time. Memory use is bounded by one frame (≤ 65552 bytes). It
authenticates and fully validates a frame before releasing any of its records. It stops at:

- end of file after a valid final frame → complete (`io.EOF`);
- end of file at a frame boundary or inside a frame, with no final frame → incomplete (`ErrIncomplete`); every record
  yielded before is authentic (HP-REC-009);
- an invalid length, a frame that fails authentication, an invalid record or footer, or bytes after the final frame →
  corrupt (`ErrCorrupt`). Records yielded before the failure are authentic.

**Verification** (`Verify`, PLAN §13.7) reports `ok` (all frames authentic, valid final frame, nothing after it),
`interrupted` (all frames present authentic, no final frame) or `corrupt` (header, slots or a frame invalid). It also
reports frames, records, seq range, the offset of the end of the valid prefix, `ciphertext_sha256` of the valid prefix,
`H`, and the state of both slots. The database layer compares `H` and `ciphertext_sha256` with its records and assigns
`missing`/`orphan`.

**Recovery** (`Recover`, PLAN §13.6 step 2) is for a `.partial` file found at startup. It authenticates frames from the
start and stops at the first failure or at the end. If bytes follow the valid prefix, it first copies the whole original
to a caller-supplied quarantine path (`O_EXCL`, 0600, fsynced), then truncates the partial file to the valid prefix
and fsyncs. It then renames the file to its final name and fsyncs the directory. The result is *complete* if a valid
final frame was found (a crash between the final fsync and the rename), otherwise *interrupted*. If the header or slots
are unusable it changes nothing and returns an error; the caller quarantines the file. Recovery treats any failing
frame as the end of the valid prefix, including one in the middle of the file. This is why the original is preserved
before truncation.

## 11. Versioning policy

- The magic `HPREC1\n\0` fixes the container layout: prefix, header framing, slot size and layout, frame framing,
  STREAM nonce and AEAD, and record framing. Any change to these requires a new magic (`HPREC2…`). Readers seeing
  `HPREC` followed by another version report an unsupported version.
- The header `v` fixes the record-type registry and payload encodings within HPREC1. New record types or payload fields
  require `v` = 2. Readers reject a `v` they do not implement, rather than skipping unknown records, because a recording
  that silently loses events would violate HP-REC-011.
- Record type codes and names are never reused or renumbered.
- Writers only ever write the newest version they implement. Readers keep support for every version that may still
  exist within the retention period.

## 12. Refinements of PLAN §13.3

These do not relax any requirement. They make the format precise enough to implement independently:

1. **Binary key slots** (`HPK1` layout with a SHA-256 checksum) instead of zero-padded JSON
   `{"gen","key_id","wrap":"A256GCM","nonce","wrapped_dek"}`. The wrap algorithm and nonce are inside the opaque
   `wrapped` value produced by the caller's `DEKWrapper` (the keyring's sealed format). The checksum gives torn-write
   detection independent of the wrapper.
2. **`prev_segment_sha256`** is defined as the previous segment's `ciphertext_sha256`, lowercase hex. It is required
   for `ordinal` > 0 and MUST be empty for `ordinal` 0.
3. **Record timestamps**: the base is `created_at` (µs), reset at the start of every frame.
4. **Records never span frames**, frames are never empty, and the maximum record payload is 65472 bytes.
5. **`ciphertext_sha256`** covers the frames region only (§8).
6. **Footer**: a fixed binary payload, canonical record fields, `plaintext_sha256` as defined in §7.4. It is placed in a
   footer-only final frame when it does not fit.
7. **Canonical decoding everywhere**: minimal varints, canonical header re-encoding, no trailing bytes, zero slot
   padding. Every accepted file has exactly one encoding of its content.
8. **Recovery** copies the original to quarantine only when bytes are actually discarded.

## 13. Security properties and limits

What the format provides, for an attacker **without** the recording key or KEK:

- **Confidentiality** of all recorded content (ChaCha20-Poly1305 under a per-segment key). Header fields (IDs, times,
  kind, ordinal) are plaintext metadata.
- **Integrity and ordering.** Modifying, reordering, duplicating, deleting or inserting frames, or moving frames
  between segments, fails authentication (counter nonce, per-segment key, `H` as AD).
- **Truncation detection.** Without the authenticated final-flag frame, a segment is never reported complete.
  Truncation (at a frame boundary or inside a frame) is reported as *interrupted*, not *corrupt*. It is distinguished
  from a genuine crash only by comparing with the database state (a `finalized` row whose file verifies as `interrupted` has
  been tampered with).
- **Header binding.** Changing any header byte changes `H`, so the DEK no longer unwraps and no frame authenticates.
- **Nonce uniqueness.** Each segment has a fresh random DEK and salt, and the frame counter never repeats within a
  segment, so (K, nonce) pairs are never reused.
- **Crash consistency.** Established segments always keep an authentic, replayable prefix. Loss is bounded by the
  caller's flush policy (≤ 250 ms in group mode).

Limits:

- **A key holder can forge.** Anyone with the KEK (or the recording purpose key) and write access can create a fully
  consistent segment, including the footer and hashes. Tamper evidence against such an attacker comes only from
  the MAC'd integrity chain in SQLite plus **external anchoring** (`hallpass anchors export`, HP-CRY-008). Anchoring
  protects history up to the last exported anchor, not data written after a compromise (THREAT_MODEL T-12, T-15).
- **Whole-file substitution and deletion** are not detectable from the file alone. Each file is self-consistent, so
  verification MUST compare `H`, IDs and `ciphertext_sha256` with the database, and the database with anchors.
- **Slot metadata** (`gen`, `key_id`) is unauthenticated. Tampering can cause fallback to the other slot or loss of
  access (denial of service), never a different plaintext. `Verify` reports the state of both slots.
- **No key commitment.** ChaCha20-Poly1305 and AES-GCM are not key-committing. DEK authenticity relies on the wrapper's
  AEAD with the segment-bound AAD. A party able to produce a valid wrapping already holds the wrapping key (see above).
  Flagged for the external review.
- **Metadata leakage.** File size, frame count and sizes, and flush timing reveal activity volume and rhythm.
- **Memory.** Keys exist in process memory while in use. Zeroization is best effort (Go may copy).

## 14. Review status

**Needs external cryptographic review (R-02).** The construction composes standard primitives (HKDF-SHA256,
ChaCha20-Poly1305 in STREAM, SHA-256, a caller AEAD for key wrapping) from the Go standard library and
`golang.org/x/crypto`. No primitive is implemented here. The composition, the slot design, the recovery semantics and
the limits above have not had independent review. Until review, release notes must say so (RG-9).
