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
| KEK | Back up, stop the server, `hallpass keys init-kek --out NEW`, `hallpass keys rotate-kek --new NEW`, set `kek.file` to NEW, start, back up | Every purpose key is rewrapped in one transaction and the old KEK stops working. Keep the old KEK until backups made with it have expired. |

A wrong or rotated-away KEK is detected at startup ("master key (KEK) does not match this data directory") and the server refuses to start.

## Limits

Keys exist in process memory while Hallpass runs. Anyone who controls the running process, or holds both the host and the KEK,
can decrypt everything (see `docs/THREAT_MODEL.md` §1). KMS/HSM-backed wrapping is a review item (R-03).
