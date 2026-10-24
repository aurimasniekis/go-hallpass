# Keys and the KEK

HallPass encrypts sensitive data with a two-level key hierarchy. The **KEK** (key-encryption key, the master key) is a
32-byte file outside the data directory. It wraps purpose keys stored in the database, which encrypt:

| Purpose | Protects |
|---|---|
| `field` | Request reasons, comments, TOTP seeds, OIDC client secrets, provider tokens |
| `credential` | Destination login private keys, user and host CA keys, the gateway SSH host key |
| `recording` | The random per-segment key of every recording file |
| `manifest` | MACs over the recording integrity chain |
| `token` | HMACs of one-time tokens, recovery codes and approval action tokens |

Encryption is AES-256-GCM, with each value bound to its table, column and row. Reference:
[keys.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/keys.md).

## Rules for the KEK

- Create it once with `hallpass keys init-kek --out FILE` (mode `0400`; refuses to overwrite).
- It must be owned by the service user, readable only by it, and **outside** `data_dir`. Production mode refuses
  anything else.
- **Back it up offline, in at least two places, separately from data backups.** Backups never contain the KEK. Without
  it, nothing can be recovered, by design.
- Never put it in the configuration file, the data directory, an image, a Compose file or version control.
  `kek.source: env` (`HALLPASS_KEK`) exists but is discouraged.

`hallpass keys status` shows the KEK ID (a non-secret fingerprint) and the purpose-key versions. Like other offline
commands it needs the service stopped.

## Rotation

| What | How |
|---|---|
| A purpose key | `hallpass keys rotate --purpose field` (offline). The new version becomes active; a background job re-encrypts existing rows, after which `hallpass keys retire --purpose field --version N` retires the old version. |
| The KEK | Back up, stop, `hallpass keys init-kek --out NEW`, `hallpass keys rotate-kek --new NEW`, point `kek.file` at `NEW`, start, back up again. Keep the old KEK until backups made with it have expired. |

Audit details and recording segment keys are exceptions to background re-encryption; read the reference before
retiring versions.

## Gateway host key

The key agents pin. `hallpass hostkey show` prints it. To rotate without breaking agents:

1. `hallpass hostkey stage` (offline). The new key's algorithm must differ from the active one: the default is
   `ecdsa-sha2-nistp256`, or pass `--algorithm ssh-ed25519` when the active key is ECDSA. The gateway then serves both
   keys.
2. Distribute the new `known_hosts` line to every agent.
3. `hallpass hostkey promote`.

## Limits

Keys live in process memory while HallPass runs. Anyone who controls the running process, or holds both the host and
the KEK, can decrypt everything. Wrapping keys with a KMS or HSM is not supported yet.
