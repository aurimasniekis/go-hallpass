# Gateway exit codes

For `exec` and `connect`, the destination's exit status is passed through unchanged. The codes below are used
only when the gateway itself ends the command. `ssh <gateway> help exit-codes` prints the same table. With `--json`, or
whenever stderr is not a terminal, the gateway also writes one `hallpass.error/v1` line to stderr whose `exit_code`
and `code` match this table.

| Exit | `code` | Meaning |
|---:|---|---|
| 0 | `ok` | Gateway-only command succeeded. |
| 80 | `internal` | Internal or storage failure, gateway degraded, shutdown, or a mandatory recording could not be written. |
| 81 | `usage` | Parse error, unknown option, ambiguous role, invalid duration, control characters in the command. |
| 82 | `not_found_or_forbidden` | Target, role or request unknown or not permitted (deliberately indistinguishable). |
| 83 | `denied` | Request denied. |
| 84 | `expired` | Request expired before a decision. |
| 85 | `canceled` | Request canceled. |
| 86 | `wait_timeout` | Still pending after the wait timeout; the request remains pending. |
| 87 | `access_ended` | Grant expired, revoked or disabled before or during the activity; lockdown. |
| 88 | `destination_unavailable` | Destination dial, host-key verification or destination authentication failed. |
| 89 | `limit_exceeded` | Rate limit, concurrency limit or too many pending requests. |
| 90 | `input_required` | Required input (such as a reason) is missing and there is no PTY to prompt on. |

An SSH-level failure before the gateway runs anything (for example an unknown agent key) is reported by your SSH
client, usually with exit 255.
