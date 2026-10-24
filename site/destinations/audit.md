# Destination-side audit (optional)

Inside an interactive shell, Hallpass cannot tell which programs actually ran, and it never labels commands guessed
from keystrokes as verified. The optional **`hallpass-collector`** adds a second, independent source: the destination
kernel's exec audit records, signed by the collector and attached to the session timeline as **destination-reported**
events. Full reference, including the wire protocol:
[audit-collector.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/destination/audit-collector.md).

::: warning Supporting evidence, not proof
The records come from the destination. Anyone with root there can stop auditd, edit logs or forge records before they
are signed. Hallpass shows them as `verified: false` with a correlation method and a confidence level.
:::

## Requirements on the destination

- Linux with auditd and an exec rule for role accounts, e.g. `/etc/audit/rules.d/hallpass.rules`:

  ```
  -a always,exit -F arch=b64 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k hallpass
  -a always,exit -F arch=b32 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k hallpass
  ```

- `pam_loginuid` in sshd's PAM session stack (the default on most distributions).
- sshd at `LogLevel INFO` or higher, so the `Accepted publickey … ID …` line is logged.
- NTP (2 minutes of skew are tolerated).

## Install and enroll

1. Build the collector: `go build ./cmd/hallpass-collector` (a static binary).
2. Create its key on the destination; the private key never leaves the host:

   ```sh
   install -d -m 0700 /etc/hallpass-collector
   hallpass-collector keygen -key /etc/hallpass-collector/key
   ```

3. In Hallpass, register a collector for the server (the **Destination audit** tab on the server page) with the
   printed public key. Note the collector ID (`dac_…`).
4. Run it as root, for example from a systemd unit:

   ```
   [Service]
   ExecStart=/bin/sh -c 'tail -F -n0 /var/log/audit/audit.log /var/log/auth.log | \
     /usr/local/bin/hallpass-collector run -url https://hallpass.example.com -collector-id dac_… \
       -key /etc/hallpass-collector/key -state /var/lib/hallpass-collector/seq'
   StateDirectory=hallpass-collector
   Restart=always
   ```

   On journald-only systems use `journalctl -f -o short -u ssh -u sshd` instead of the auth log. Use `-dry-run` to
   check what would be sent.

## How records are matched to sessions

- **Certificates (recommended, high confidence):** each login carries a certificate key ID naming the grant and the
  connection, so matching is exact.
- **Managed login keys (medium confidence):** the key is shared by all sessions of a role, so a record is attached
  only when exactly one session used the key at that time. Otherwise it is refused as `ambiguous`. Only logins with
  fingerprints or accounts you list (`-fingerprint`, `-account`) are shipped.
- Records from processes that kept running after the session ended are still attached for up to 24 hours, flagged
  `after_session_end`. That is how you spot detached processes.

## Limits

Shell built-ins (`cd`, `echo`, redirections) execute nothing and leave no record. Interpreters show the interpreter,
not the script. auditd can drop events under load. A missing record proves nothing.
