# Keys and encryption at rest

Hallpass encrypts sensitive data with a two-level key hierarchy (ADR-0004):

```
KEK (master key, 32 bytes, outside data_dir)
 └─ wraps (AES-256-GCM) purpose keys stored in the database, one active version each:
     field       sensitive columns: request reasons, comments, TOTP seeds, OIDC client secrets, provider tokens
     credential  destination login private keys, user/host CA keys, the gateway SSH host key
     recording   wraps the random per-segment key of every recording file
     manifest    MACs over the recording integrity chain
     token       HMACs of one-time tokens, recovery codes and approval action tokens
```

Sealed values are `0x01 | key version | 96-bit random nonce | AES-256-GCM ciphertext`. The associated data binds each value to
its table, column and row, so a value moved to another row or column fails to decrypt.

## Provisioning the KEK

```sh
hallpass keys init-kek --out /etc/hallpass/kek      # creates a 0400 file; refuses to overwrite
chown hallpass: /etc/hallpass/kek
```

- **Production refuses to start without a KEK** and refuses a KEK file inside `data_dir`, accessible by group or others,
  or owned by another user.
- `kek.source: env` reads base64 from `HALLPASS_KEK`. Prefer files or secret mounts, because environments leak more easily.
- Development mode without `kek.file` generates `<data_dir>/dev-kek`. Production configuration can never use it.
- `hallpass keys status` shows the KEK ID (a non-secret fingerprint) and key versions. The server must be stopped for offline
  commands because they take the data-directory lock.

## Backing up the KEK (critical)

**Losing the KEK makes every encrypted value and recording permanently unrecoverable.** Database backups never contain the KEK,
by design. Keep at least two offline copies of the KEK, stored separately from data backups and with stricter access. A backup
manifest records the KEK ID so restore can check that the right key is supplied.

## Rotation

| What | How | Effect |
|---|---|---|
| Purpose key | `hallpass keys rotate --purpose field` (offline) or the storage page (online, WP20) | New version becomes active. Old versions stay decrypt-only until the background job has re-encrypted everything, then they are retired. |
| KEK | Back up, stop the server, `hallpass keys init-kek --out NEW`, `hallpass keys rotate-kek --new NEW`, set `kek.file` to NEW, start, back up | Every purpose key, including retired versions, is rewrapped in one transaction and the old KEK stops working. Keep the old KEK until backups made with it have expired. |

A wrong or rotated-away KEK is detected at startup ("master key (KEK) does not match this data directory") and the server refuses to start.

## Limits

Keys exist in process memory while Hallpass runs. Anyone who controls the running process, or holds both the host and the KEK,
can decrypt everything (see `docs/THREAT_MODEL.md` §1). KMS/HSM-backed wrapping is a review item (R-03).

## Background re-encryption after purpose-key rotation

After `hallpass keys rotate <purpose>`, a background job (`keyring.reseal`, every 6 hours, 500 rows per column per
run) re-seals encrypted fields under the new active version:
- request reasons, decision comments, key revocation reasons, TOTP secrets, outbox bodies and destination-audit exec
  details (`field`);
- integration secrets and private keys (`credential`);
- OIDC client secrets.

Each row is compare-and-set, so concurrent updates are never overwritten.

Exceptions:
- **Audit details** are never re-sealed, because the audit hash chain covers their ciphertext. `field` key versions used
  by audit rows stay `decrypt_only`.
- **Recording segment keys** live in the HPREC1 key slots. A separate job (`recording.rewrap`, every 6 hours) rewraps them:
  for each finalized, interrupted or failed segment still on an old `recording` version, it writes the inactive key slot of
  the file under the active key, fsyncs it, then updates the database copy of the wrapped key (compare-and-set). A segment
  without a file (`missing`) has only its database copy rewrapped. Segments still being written are rewrapped after they
  are finalized. The file's other slot keeps the old wrapping until a later rewrap or startup slot repair overwrites it;
  readers use the newest slot that unwraps.
- **Token MACs** (recovery codes, invitation/reset/setup tokens, chat link codes, approval action tokens) cannot be
  re-computed, because only their MAC is stored. Rotating the `token` key keeps old versions `decrypt_only`, so
  invitation, reset and setup tokens and in-flight OIDC logins keep working. **Known gap (security review SR-36):** recovery codes, chat link codes and approval
  action tokens are currently looked up with the active version only, so a `token` rotation invalidates the existing ones.
  Regenerate recovery codes after rotating the token key.
- **Integrity-chain MACs** (`manifest`) are never re-computed and `manifest` versions are never retired.

### Startup key-slot repair

At every start, before accepting connections, Hallpass checks the key slots of every finalized or interrupted segment. If a
slot no longer unwraps but the database copy of the wrapped segment key does (it is bound to that segment's ID and header
hash, so it cannot be substituted), the copy is written into the unusable slot (PLAN §13.4). This recovers a file whose
slots were damaged, a file restored from an older copy after its key was rotated and retired, and refreshes slots that
only hold a retired key. Repairs are logged.

### Retiring an old version

`hallpass keys retire --purpose P --version N` (offline) refuses while the version still protects data:

| Purpose | Retirable when |
|---|---|
| `field`, `credential` | No sealed column (including audit details for `field`) still uses it. |
| `recording` | No segment other than `deleted` ones still uses it: wait for `recording.rewrap`. `missing` segments are rewrapped in the database only. |
| `token` | No OIDC login state is sealed with it, and no unused recovery code, and no unused and unexpired one-time token, chat link code or approval action token was created before version N+1 became active. |
| `manifest` | Never. |

Retired versions are not loaded. Their wrapped key stays in the database.
