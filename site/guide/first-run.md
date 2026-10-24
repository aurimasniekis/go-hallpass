# First run

You have a running HallPass and the one-time setup link from `hallpass admin bootstrap`. This page creates the first
administrator, enrolls two-factor authentication and onboards your first server.

## Create the first administrator

Open the setup link (`https://<your host>/setup?token=…`). The token is removed from the address bar as soon as the
page loads. Enter an email, a display name and a password (at least 12 bytes by default).

<Shot name="setup-admin" alt="The Set up HallPass page with administrator email, display name and password" />

If the link expired (30 minutes) or was already used, stop the service and run `hallpass admin bootstrap` again. It
refuses once an administrator exists.

## Enroll two-factor authentication

Scan the QR code with an authenticator app (or type the secret), then enter the 6-digit code. HallPass shows
**recovery codes** once: store them somewhere safe and tick *I have stored this securely*. Operators you invite later
go through the same enrollment when their account requires MFA.

<Shot name="mfa-enroll" alt="Two-factor enrollment with the QR code and secret masked" caption="Enrollment screen (QR code and secret masked in this screenshot)" />

You land on the dashboard. Everything is empty, and policy is **default deny**: no agent can see anything yet.

## Enroll your first server

Go to **Servers → New server (guided)**. The wizard takes a server from nothing to a working login in six steps.
Everything it creates is saved as you go, so you can stop and resume from the server page with **Guided setup**.

### 1. Server

The **alias** is what agents type (`web1`). The address and port stay inside HallPass. Groups and labels are used by
policy selectors; descriptions are shown to agents but never grant anything.

<Shot name="wizard-server" alt="Onboarding wizard, step 1: server alias, description, environment, address and port" />

### 2. Host identity

Pin the server's SSH host key. **Scan host keys** fetches what the server offers, or **Add key** lets you paste it.
Compare the fingerprint with the server itself, out of band:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub     # run on the destination
```

Then **Confirm**. HallPass never trusts on first use: no credential is ever sent to a host whose key does not match.

### 3. Roles

Add one role per kind of work, for example `inspect` (remote user `ro`) and `deploy` (remote user `deploy`). Each
role has capabilities (`shell`, `exec`, `pty`), a default and a maximum duration, and recording settings. Use a
separate, least-privilege account per role on the destination.

### 4. Login credentials

For each role, **Generate login key**. HallPass keeps the private key encrypted and shows the line to install on the
destination, already restricted with `restrict` and `from="<gateway egress address>"`:

<Shot name="wizard-credentials" alt="Login credential step with the authorized_keys line, a successful login test and the Activate button" />

Install the line in the remote user's `~/.ssh/authorized_keys`, press **Test login**, then **Activate**. Instead of
keys, you can use **certificates** signed by a HallPass user CA; see [Servers and roles](/operators/servers).

### 5. Access

Choose which agent groups may use the server, and whether requests need approval or are approved automatically. You
can also create an **approver rule** here: even administrators can approve only within an approver rule.

<Shot name="wizard-access" alt="Access step: agent groups, roles, access level, maximum duration, reason and approvers" />

### 6. Summary

<Shot name="wizard-done" alt="Summary: server exists, host verified, roles defined, logins active, access rule present" />

## Next

[Connect your first agent](/guide/first-agent). Before production use, also set up
[backups](/operators/backup) and read the [security model](/security/).
