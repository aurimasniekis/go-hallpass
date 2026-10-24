# Destination audit collector (optional)

HallPass records what crosses the gateway. Inside an interactive shell it cannot tell which programs actually ran, and it
never labels commands inferred from keystrokes or output as verified. The optional destination audit
integration adds a second, independent source: the destination kernel's exec audit records, shipped by a
small signed collector and attached to the access-session timeline as **destination-reported** events.

> **Trust.** These records come from the destination, which HallPass treats as untrusted. HallPass checks that a batch
> was signed by the enrolled collector, is not a replay, and is consistent with its own session state. It cannot check
> that the destination told the truth. Anyone with root on the destination can stop auditd, edit logs, or forge records
> before they are signed. Treat destination audit as supporting evidence, never as proof.

## What you get

Each exec record that HallPass can attribute to an access session becomes a `destination.exec` timeline event (schema
version 1, shown as `destination.exec@1`). Its plaintext data holds metadata only:

| Field | Meaning |
|---|---|
| `provenance` | always `destination-audit` |
| `verified` | always `false` |
| `source` | `auditd` |
| `correlation` | `certificate_key_id`, `login_key_time_window` or `login_binding` (see below) |
| `confidence` | `high` (certificate) or `medium` (managed key) |
| `reported_at` | exec time according to the destination clock |
| `after_session_end` | `true` when the process ran after the access session ended (a detached process) |
| `pid`, `ppid`, `uid`, `auid`, `success` | as reported by the kernel audit record |
| `argc`, `argv_bytes`, `truncated` | size of the command line |
| `collector_id`, `record_id` | where the record came from and its stored ID |

The executable path, arguments and working directory can contain secrets, so they are not stored in the timeline.
They are sealed with the field key in `destaudit_records.details_enc` and are only returned by the record-details API,
which needs the same permission as recording playback. Retention purges them together with the session's
timeline payloads and leaves a tombstone row.

The timeline position (`seq`) is the time HallPass ingested the record, which can be later than surrounding events.
Use `reported_at` to place it.

## How correlation works

The collector never sends a HallPass session ID, and HallPass would not trust one. It reports what sshd and the kernel
logged, and HallPass checks that against its own state:

1. **Certificates (recommended, `confidence: high`).** When a role uses HallPass user certificates, each destination
   login carries a certificate key ID `hallpass:<role>:<grant>:<connection>`, and sshd logs it after it has verified
   the certificate. HallPass accepts a record only if the grant exists, belongs to the collector's server and to that
   role, the destination account equals the grant's remote user, the connection had a channel in that access session,
   and the login and exec times fall inside the session's lifetime (± clock skew).
2. **Managed login keys (`confidence: medium`).** A managed key is shared by every session of its role, so the key
   fingerprint only narrows the role. HallPass accepts the record only if **exactly one** access session had a
   channel using that credential at the login time (± skew). With overlapping sessions on the role the record is
   refused as `ambiguous`; it is never guessed. Use certificates where sessions on a role overlap.
3. **Login binding.** The first accepted record of a destination login (audit session) binds that login to the access
   session. Later records of the same login use the binding (`login_binding`), and a record that would move the login to
   another session is refused (`login_conflict`).

Records from up to 24 hours after the session ended are still attached, flagged `after_session_end: true`: the
process kept the login's audit session after HallPass closed the SSH connection. That is the signal for detached
processes (see the [hardening guide](hardening.md#5-process-lifecycle-after-access-ends)).

The `HALLPASS_SESSION` environment-variable marker that the plan mentioned is **not** used. The agent controls which
environment variables it sends, so a marker would be agent-forgeable.

Refused records are not stored. HallPass returns the reason for each one to the collector, which logs it:
`no_identity`, `invalid_key_id`, `unknown_session`, `unknown_key`, `server_mismatch`, `role_mismatch`, `user_mismatch`,
`connection_mismatch`, `outside_window`, `no_session`, `ambiguous`, `login_conflict`, `future_timestamp`, `too_old`,
`duplicate_in_batch`, `too_large`, `invalid_*`.

## Requirements on the destination

- Linux with auditd and an exec rule for the role accounts, for example in `/etc/audit/rules.d/hallpass.rules`:

  ```
  -a always,exit -F arch=b64 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k hallpass
  -a always,exit -F arch=b32 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k hallpass
  ```

  Drop the `b32` line on hosts without 32-bit syscall support.

- `pam_loginuid` in sshd's PAM session stack (the default on most distributions). It assigns the audit session (`ses`)
  and writes the `LOGIN` record that ties it to the sshd process.
- sshd logging at `LogLevel INFO` or higher, so the `Accepted publickey … ID <key id>` line reaches syslog or the journal.
- NTP. The default clock-skew tolerance is 2 minutes.

## Install and enroll

1. Build or install `hallpass-collector` (a static Go binary: `go build ./cmd/hallpass-collector`).
2. Create the collector key on the destination. The private key never leaves the host:

   ```
   install -d -m 0700 /etc/hallpass-collector
   hallpass-collector keygen -key /etc/hallpass-collector/key
   ssh-ed25519 AAAAC3Nz… hallpass-collector@web1
   ```

3. In HallPass, register a collector for the server with that public key (admin permission and recent authentication).
   HallPass returns the collector ID (`dac_…`).
4. Run the collector as root (it must read the audit log), for example as a systemd service:

   ```
   [Service]
   ExecStart=/bin/sh -c 'tail -F -n0 /var/log/audit/audit.log /var/log/auth.log | \
     /usr/local/bin/hallpass-collector run -url https://hallpass.example.com -collector-id dac_… \
       -key /etc/hallpass-collector/key -state /var/lib/hallpass-collector/seq'
   StateDirectory=hallpass-collector
   Restart=always
   ```

   On journald-only systems, replace the auth log with `journalctl -f -o short -u ssh -u sshd`. `-o short` keeps the
   `sshd[<pid>]` prefix that the collector needs.

Logins that began before the collector started cannot be resolved and are skipped. Revoking the collector in HallPass
stops ingestion immediately. Rotate the key by registering a new collector and then revoking the old one.

### `run` flags

| Flag | Meaning |
|---|---|
| `-url` | HallPass base URL. Records go to `<url>/hooks/destaudit/<collector-id>`. Must be `https://`. |
| `-collector-id`, `-key` | enrollment ID and private key path (the key file must be mode `0600` or stricter) |
| `-state` | persists the last accepted batch sequence number |
| `-ca-file` | PEM bundle to verify HallPass's TLS certificate (default: system roots) |
| `-fingerprint SHA256:…` | also ship logins made with this managed login key (repeatable) |
| `-account NAME` | also ship public-key logins of this account (repeatable) |
| `-flush-interval` | how often to ship (default 5s) |
| `-dry-run` | print records as JSON lines and send nothing, useful for checking the rules and inputs |
| `-allow-insecure-http` | testing only: permits `http://`, which sends exec arguments unencrypted |

By default only logins with a HallPass certificate key ID are shipped. Managed-key logins are shipped only when you list
the key's fingerprint (shown on the role's credential page) or the account. Other users' activity stays on the host.

Input files given as arguments are read in order, then the collector ships and exits. Without arguments it reads stdin
until EOF.

## Input format

The reference collector reads lines in any interleaving:

- **auditd raw lines**, as written to `/var/log/audit/audit.log` or printed by `ausearch --raw`, optionally prefixed
  with `node=<host>`. It uses `SYSCALL`, `EXECVE`, `CWD` and `EOE` records that share one event stamp
  (`msg=audit(<sec>.<ms>:<serial>)`), plus `LOGIN` records (`pid`, `ses`). Quoted values are literal; unquoted string
  values are hex-decoded. Split arguments (`aN_len`, `aN[i]`) are joined. The ENRICHED suffix after `0x1d` is ignored.
- **sshd acceptance lines**:
  `sshd[<pid>]: Accepted publickey for <user> from <addr> port <port> ssh2: <TYPE> SHA256:<fp>[ ID <key id> (serial <n>) CA <type> SHA256:<fp>]`
  (also `sshd-session[<pid>]`).

An exec belongs to a login when its `ses` matches a `LOGIN` record whose `pid` is the sshd process that logged the
acceptance line. Execs with no audit session (`ses=4294967295`), such as cron and daemons, are never shipped. Argument
lists are truncated to 256 arguments and 16 KiB, and `truncated` is set when that happens.

## Wire protocol

`POST /hooks/destaudit/{collector_id}` with `Content-Type: application/json` and a body of at most 1 MiB:

```json
{"payload": "<base64 of the batch JSON>", "signature": "<base64 Ed25519 signature>"}
```

The signature is pure Ed25519 over `"hallpass-destaudit-batch-v1\x00" || payload`. HallPass verifies it before it parses
the payload. The payload is a strict JSON batch: unknown fields are rejected, and so is any session ID a collector
might add.

```json
{"v": 1, "collector_id": "dac_…", "seq": 1792756800000000, "sent_at": "2026-10-23T12:00:00Z",
 "records": [{"id": "1792756801.200:510", "source": "auditd", "time": "2026-10-23T12:00:01.2Z",
   "login": {"ref": "1792756800.100:500/7", "user": "ro", "cert_key_id": "hallpass:rol_…:grt_…:con_…",
             "time": "2026-10-23T12:00:00.1Z"},
   "pid": 2010, "ppid": 2005, "uid": 1001, "auid": 1001, "success": true,
   "exe": "/usr/bin/cat", "argv": ["cat", "-n", "/tmp/my file"], "cwd": "/home/ro"}]}
```

- **Replay protection:** `seq` must be strictly greater than the last accepted sequence for the collector. The reference
  collector uses `max(last + 1, now in µs)`, so it keeps working after losing its state file. An exact resend of an
  accepted batch returns the stored result (`duplicate_batch: true`). Any other batch at or below the last sequence gets
  `409` with `last_seq`, and the collector re-signs above it. Record IDs are unique per collector, and repeats count as
  `duplicates`.
- **Bounds:** `sent_at` must be within 2 minutes of HallPass's clock. Records may be at most 24 hours old and no later
  than now plus 2 minutes. A batch holds at most 500 records.
- **Responses:** `200` with `{seq, records, accepted, duplicates, rejected, rejections[]}`. `400` for a malformed
  batch, clock skew or a mismatched `collector_id`. `401` for an unknown or revoked collector or a bad signature; the
  three are indistinguishable. `409` replay. `413` body too large. `415` wrong content type. `503` storage unavailable.
- **Audit:** every accepted batch writes one `destaudit.batch.ingested` audit event (actor `provider`,
  `destaudit:<collector id>`) with counts. Failed signature checks are logged, not audited, so unauthenticated traffic
  cannot grow the audit log.

Test vector (Ed25519 seed `00 01 02 … 1f`):

```
public key  03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
payload     {"v":1,"collector_id":"dac_00000000000000000000000000","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[]}
signature   253247ae406e02bc28f65571b0da67e5f1a81795d690813927f288eb7a22ab6fa6470e580a76685034d24ceda2b083e448aef47fd7889887a3c18060c1ed2b09
```

## Limits of kernel exec auditing

- **Built-ins are invisible.** `cd`, `echo`, `export`, `read`, redirections, `source` and shell functions do not exec
  anything, so `echo secret > file` leaves no exec record. Interpreters (`python -c`, `bash -c`, `awk`) show the
  interpreter and its arguments, not what the script did.
- **It shows the exec, not the intent.** You see `/usr/bin/curl` with arguments, not why it ran or what came back.
- **Shell history is not evidence.** `HISTFILE` and `PROMPT_COMMAND` logs are written by the session itself, which can
  disable, edit or forge them. The collector does not read them.
- **Root can lie.** A user who can become root can stop auditd, delete rules, edit logs before the collector reads
  them, or read the collector key and sign forged records. Enforce least privilege (no broad `sudo`) and ship logs off
  the host quickly. Revoke the collector in HallPass after any suspected compromise.
- **Gaps are possible.** auditd can drop events under load (`backlog_limit`, `disk_full_action`), the collector skips
  logins it did not see start, and refused records are not stored. A missing record proves nothing.
