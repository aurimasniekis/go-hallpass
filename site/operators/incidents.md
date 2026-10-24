# Incident runbooks

Short versions of the runbooks. Every action here is audited. The full runbooks, with API calls, are in
[incidents.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/incidents.md).

Prepare before you need them: export [integrity anchors](/operators/backup#integrity-anchors) regularly, keep the KEK
backed up offline, and alert on `/readyz`, disk usage and recording failures ([Monitoring](/operators/monitoring)).

## Lockdown

Use it when you cannot yet tell what is affected. **Dashboard → Enable lockdown** (type the confirmation phrase):

- every active grant is revoked; gateway-managed channels end within 5 seconds;
- pending requests are canceled; new requests and channels are refused;
- agents can still connect and run `list` and `status`.

Lifting it is administrator-only and needs a fresh login. Revoked grants are not restored; agents request again.

## Suspected agent compromise

Signs: unexpected requests or reasons, unusual source addresses, destination audit records that do not match the
agent's task.

1. **Contain:** revoke the agent's key or disable the agent. Its live channels end within 5 seconds.
2. **Pin history:** `hallpass anchors export --since <last shipped seq>` and ship it.
3. **Review** its requests, sessions and recordings. Treat everything it printed or typed as untrusted.
4. **Rotate** the login credential of every role it had a shell on, and check destinations for persistence (cron,
   `authorized_keys`, systemd units, detached processes).
5. Issue a new key only once the cause is understood.

## Suspected gateway compromise

Assume the attacker can read all recordings and credentials and act as Hallpass toward every destination.

1. Enable lockdown if the console is still trustworthy. Isolate the host; keep its disk for forensics.
2. On every destination, remove Hallpass `authorized_keys` lines and distrust Hallpass user CAs.
3. Build a clean host with a **new KEK**. Restore the last pre-compromise backup (rewrap it to the new KEK with
   `hallpass keys rotate-kek`), run `hallpass verify`, and compare chain heads with your anchors.
4. Rotate the gateway host key, every login credential, integration secrets, and force operator password resets.

## Destination host key changed

`exec` and `connect` fail with exit 88 and a host-key alert is recorded. Hallpass never sends credentials to a host
whose key does not match.

1. Confirm out of band whether the change is expected (reinstall, key rotation).
2. Expected: add the new key on the server's **Host identities** tab, confirm the fingerprint, retire the old one.
3. Not expected: keep the server disabled and investigate the network path and the host.

## Disk full

`/readyz` reports `degraded` (`disk_reserve`, `disk_full`). New requests and channels are refused; running channels
continue unless their recording fails.

Free space or grow the volume: usually recordings (check retention), old backups or pre-migration snapshots. Readiness
recovers without a restart.

## Database corruption

Startup refuses with `storage corrupt …`, or readiness is `failed`. Stop, keep the data directory as it is, run
`hallpass verify`, restore the latest backup that verifies, start, and compare chain heads with your anchors.

## Lost KEK

If any copy exists, restore it to `kek.file` with mode `0400` and start. If none exists, the encrypted data cannot be
recovered: install fresh with a new KEK, re-enroll servers and credentials, recreate integrations and operators.

## Locked out of administration

Break-glass recovery needs shell access to the host, the KEK and the data-directory lock. It has no remote equivalent.

```sh
systemctl stop hallpass
sudo -u hallpass hallpass admin recover --config /etc/hallpass/hallpass.yaml --email alice@example.com
# or create a new local administrator:
sudo -u hallpass hallpass admin recover --config /etc/hallpass/hallpass.yaml --email breakglass@example.com --new-admin
systemctl start hallpass
```

The command re-enables a disabled operator and prints a single-use token valid for 30 minutes. Every start then logs
a break-glass alert until an administrator acknowledges it on the **System** page.

::: warning Not yet usable from the browser
The current build prints a `/recover?token=…` link, but the web page and API endpoint that accept the recovery token
are not shipped yet. Until they are, plan around the other recovery paths: keep more than one administrator, keep
recovery codes, and do not disable password login without a tested SSO path.
:::

## Chat or IdP outage

- **Slack or Telegram down:** approve in the web console. A failed notification never changes a request.
- **IdP down:** SSO logins fail; existing sessions continue until they expire.
- **Suspected IdP or chat-account compromise:** disable the affected operators or provider mapping, unlink chat
  identities, rotate integration secrets.
