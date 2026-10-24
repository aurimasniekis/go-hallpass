# File transfer

Agents can copy files to and from servers with plain `scp` and `sftp`, under the same requests, approvals and
time-bound grants as shell access. File transfer is a separate role capability, off by default: a role allows it only
when you add **File transfer (scp, sftp)** to its capabilities. HallPass records every file operation, without storing
the files themselves.

## How it works

```
scp build.tar web1@center:/tmp/          # "center" is the agent's Host entry for the gateway
```

1. SFTP has no place for a command, so the agent puts the **server in the SSH user**: `web1@center`, or
   `web1+deploy@center` to name the role.
2. HallPass picks a role of that server with the file-transfer capability: the named one, else one the agent already
   has a grant for, then one that is approved automatically, then one it can request.
3. It reuses the agent's active grant, or creates a request and waits for approval like `connect` does.
4. It opens the SFTP subsystem on the server as the role's remote account, with the role's login key, and follows
   the SFTP traffic in both directions without changing it.

Current OpenSSH `scp` uses SFTP underneath, so both tools work the same way. The old scp protocol (`scp -O`) is
refused with a hint, and so is every SSH subsystem other than SFTP. `rsync` over SSH is not supported.

The SSH user only selects the server and role. The agent is still identified by its key alone, and policy decides
what it may use: a server it may not see gets the same `not found or not permitted` answer as one that does not
exist.

## Set up a role

1. **Servers → web1 → Roles**, then create a role or edit one, and add **File transfer (scp, sftp)** to its
   capabilities. A role can have it alone, so it can move files but not run commands.
2. Pick the remote account with care: it decides which files can be read and written. A dedicated account that owns
   only the upload directory is the safest choice.
3. Policy rules, approvers, durations and **Approvers needed** work as for any role.

Optionally, lock the account down to SFTP on the server itself, so even a mistaken role change cannot give it a
shell:

```
# /etc/ssh/sshd_config on the destination
Match User upload
    ForceCommand internal-sftp
    ChrootDirectory /srv/upload        # owned by root, not writable by the user
    AllowTcpForwarding no
```

The suggested `authorized_keys` line for the role's login key (with `restrict` and `from=`) works for SFTP as is.

## Reasons

scp cannot send a reason. If the role requires one, the transfer fails with a message telling the agent to request
access first:

```sh
ssh center 'request web1 --role deploy --reason "Upload release 1.4.3" --wait'
scp build.tar web1+deploy@center:/srv/app/
```

## What is recorded

Every completed operation appears in the session timeline and the audit trail:

| Operation | Recorded |
|---|---|
| Upload, download | Path, bytes, and the SHA-256 checksum when the file moved in order from the start (scp and sftp `put`/`get` do) |
| Rename, link | Old and new path |
| Delete, create or remove directory, change attributes | Path |
| Directory listing | Path |
| Failure | The operation and the server's error, for example `Permission denied` |

Each transfer ends with a summary: files, bytes uploaded and downloaded. File contents are not stored. Paths are shown
as text with control characters replaced. A session lists at most 5000 operations; any beyond that are counted in the
summary.

The checksum lets you compare a recorded upload with the file on the server (`sha256sum`) or with a build artifact.
It is missing for resumed or parallel transfers, which write out of order.

## Limits

- HallPass does not restrict paths. The remote account's permissions, or a chroot as above, decide what is reachable.
- Grant expiry, revocation, lockdown and the idle timeout end a transfer like any other session. An interrupted
  upload leaves a partial file on the server.
- A role with `shell` or `exec` can still move data with `cat` or `curl`; that traffic is recorded as the shell or
  command output, not as file operations.
