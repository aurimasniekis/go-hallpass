# Exit codes

For `exec` and `connect`, the destination's exit status passes through unchanged. The codes below are used only when
the gateway itself ends the command. `ssh center help exit-codes` prints the same table.

| Exit | `code` | Meaning | What to do |
|---:|---|---|---|
| 0 | `ok` | Gateway-only command succeeded. | |
| 80 | `internal` | Internal or storage failure, gateway degraded or shutting down, or a mandatory recording could not be written. | Retry later; operators check `/readyz` and the logs. |
| 81 | `usage` | Parse error, unknown option, ambiguous role, invalid duration, control characters in the command. | Fix the command. Quote values with spaces ([quoting](/agents/#quoting)). |
| 82 | `not_found_or_forbidden` | Server, role or request unknown or not permitted (deliberately indistinguishable). | Check `ssh center list`; ask an operator about policy. |
| 83 | `denied` | Request denied. | Do not retry the same request; talk to a human. |
| 84 | `expired` | Request expired before a decision. | Request again if still needed. |
| 85 | `canceled` | Request canceled. | |
| 86 | `wait_timeout` | Still pending after the wait timeout. The request stays pending. | `ssh center status <req_id> --wait` |
| 87 | `access_ended` | Grant expired, revoked or disabled before or during the activity, or lockdown. | Request again if still needed. |
| 88 | `destination_unavailable` | Destination dial, host-key verification or destination login failed. | Operators: check reachability, host identity and login credentials. |
| 89 | `limit_exceeded` | Rate limit, concurrency limit or too many pending requests. | Wait; reuse pending requests. |
| 90 | `input_required` | Required input (such as a reason) is missing and there is no PTY to prompt on. | Pass `--reason`. |

A destination command can also exit with a code in 80–90. When it matters, look for the `hallpass.error/v1` line on
stderr (always present for gateway errors with `--json`, and whenever the gateway sees no terminal): no such line
means the code came from the destination.

An SSH-level failure before the gateway runs anything, such as an unknown agent key, is reported by your SSH client,
usually as exit **255**.
