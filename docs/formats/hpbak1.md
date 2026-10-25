# HPBAK1 — HallPass sealed backup object format

Status: **implemented and tested** (`internal/backup/sealed.go`). **Not externally reviewed.** An external cryptographic
review is recommended before 1.0, together with HPREC1 (DECISIONS.md R-02).

HPBAK1 seals the two objects of a remote backup that are not already ciphertext: the database snapshot and the
backup manifest (ADR-0054). Recording segments are uploaded as HPREC1 files and are not wrapped again.
The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Layout

```
offset  size        field
0       8           magic = "HPBAK1\n\0"   (48 50 42 41 4b 31 0a 00)
8       4           header_len (u32 big-endian), 1..4096
12      header_len  header: JSON object (§2)
12+N    …           frames (§4), back to back until end of object
```

`H = SHA-256(magic || header_len || header)` is the associated data of every frame.

## 2. Header

A JSON object with exactly these members (a reader MUST reject unknown members):

| Member | Type | Meaning |
|---|---|---|
| `v` | number | `1`. |
| `kind` | string | `database` or `manifest`. |
| `backup_id` | string | The backup this object belongs to (`bkp_…`). |
| `kek_id` | string | Non-secret identifier of the KEK that wrapped the data key (as in `keyring_keys.wrap_kek_id`). |
| `salt` | base64 | 16 random bytes. |
| `wrapped_dek` | base64 | The 32-byte data key wrapped by the KEK (§3). |

The header is not secret. A reader MUST check `kind` and `backup_id` against what it expects, so that an object cannot
be presented as another backup's or as the other kind.

## 3. Keys

- A writer generates a fresh 32-byte data key (DEK) and salt per object from a CSPRNG.
- The DEK is wrapped with the KEK's key wrapper (`LocalKEK`: AES-256-GCM, random 96-bit nonce, `nonce || ciphertext`)
  with associated data `"hallpass/bak/dek/v1|" + kind + "|" + backup_id`.
- The payload key is `K = HKDF-SHA256(ikm = DEK, salt = salt, info = "hallpass/bak/payload/v1")`, 32 bytes, used
  with ChaCha20-Poly1305.
- The DEK is never stored in the database: the database snapshot is the object being protected, so a key kept in it
  could not open it. Opening an HPBAK1 object needs only the KEK, like `hallpass restore`.

## 4. Frames

Each frame is `ct_len (u32 big-endian) || ciphertext`, where `ciphertext = ChaCha20-Poly1305-Seal(K, nonce_i,
plaintext_i, H)` and `16 <= ct_len <= 65536 + 16`.

- `nonce_i = BE88(i) || flag`: an 11-byte big-endian frame counter starting at 0 and one flag byte, `1` on the final
  frame and `0` otherwise (the STREAM construction, as in HPREC1).
- Every frame except the final one carries exactly 65536 bytes of plaintext. The final frame carries 0 to 65536 bytes;
  an empty object is one final frame with an empty plaintext.
- A reader opens frame `i` with flag `0`, and if that fails with flag `1`. A non-final frame shorter than 65536 bytes
  MUST be rejected. Data after the final frame MUST be rejected. An object that ends before a final frame MUST be
  rejected as truncated.
- A reader MUST NOT release the plaintext as trustworthy until it has read to the end of the final frame.

## 5. Versioning

Any change to the layout, the labels, the frame size or the primitives needs a new magic (`HPBAK2`).

## 6. Design choices

- **Same construction as HPREC1.** One STREAM implementation pattern and one review covers both formats.
- **KEK-wrapped DEK instead of a keyring purpose key.** Keyring purpose keys live in the database (wrapped by the KEK),
  which is exactly what the database snapshot contains, so they cannot protect it.
- **Bound to backup and kind.** The DEK's associated data names both, and the reader checks the header, so objects
  cannot be swapped between backups or kinds without detection. Each manifest lists the SHA-256 of every file of its
  backup, so the other objects are bound to it too.
