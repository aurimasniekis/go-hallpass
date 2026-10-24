# Sessions and recordings

Every approved grant gets an **access session**. It collects the agent's connections, each channel (`exec` command or
shell), the recordings and a timeline. Find them under **Access → Sessions**.

<Shot name="sessions" themed alt="Sessions list with open and closed sessions and their grant states" />

## The session page

<Shot name="session-overview" themed alt="Access session summary, grant, channels and recording segments" />

- **Summary and grant**: agent, server, role, remote user, the grant's remaining time and a **Revoke** button.
- **Channels**: every command and shell, how it ended and with which exit status. Gateway exit codes (80–90) mean the
  gateway ended the channel, not the destination.
- **Recording segments**: the encrypted files, their state and integrity status.
- **Destination-reported commands**: records from an optional [destination-side collector](/destinations/audit),
  clearly labeled as unverified.

### Timeline

The timeline shows what happened, in order: the decision, the grant, each connection (`C1`, `C2`, …) and its
channels (`C1·1`), commands requested by the agent, and how each ended.

<Shot name="session-timeline" themed alt="Session timeline with connections, commands and exits" />

### Replay

Pick a channel and **Load recording**. Shells replay in a terminal; `exec` commands show stdout and stderr side by
side. You can change the speed, seek, and shorten idle gaps.

<Shot name="session-replay" themed alt="Replay of an interactive shell with playback controls" />

Loading a recording decrypts it on the server, and every page read is recorded in the audit log
(`recording.played`). Only operators with the replay permission can do it (auditors and administrators; approvers when
`rbac.approver_recording_play` is set).

## Live activity

**Access → Activities** lists live channels. An approver can terminate one without revoking the grant.

<Shot name="activities" alt="Activities list" />

## Exporting

- **Export encrypted bundle**: the ciphertext and metadata, for archives.
- **Export decrypted**: JSON of the decrypted recordings. Needs recent authentication and MFA, is limited to 64 MiB,
  and is audited.

## What is and isn't recorded

- Recorded: everything the destination sends back (terminal output, stdout and stderr), `exec` command strings, and
  the lifecycle in the timeline.
- Not recorded by default: what the agent types into a shell. A role can enable `record_input`, which may capture typed
  secrets.
- Recording is **mandatory by default** and fails closed: nothing is forwarded until the recording is established, and a
  recording failure ends the channel (exit 80).
- Hallpass never claims to reconstruct "verified" commands from keystrokes. For command-level accounting, use
  [destination-side audit](/destinations/audit).

## Retention and verification

- Recordings are deleted `recording.default_retention` (90 days) after a session closes, or per role retention class.
  Tombstones remain, so verification still proves what existed.
- `hallpass verify` (offline) authenticates every segment and the integrity chain. See
  [recording.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/recording.md) and the
  [HPREC1 format](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/formats/hprec1.md).
