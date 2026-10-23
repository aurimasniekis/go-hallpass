# Fault-injection suite (HP-TST-005)

Go tests for the fault catalog in `docs/TEST_STRATEGY.md` §4. They sit behind the `fault` build tag, so
`go test ./...` and normal CI skip them.

```sh
go test -tags fault -count=1 -v ./test/fault/              # whole suite, about 2.5 min (-race adds a little)
go test -tags fault -count=1 -run TestFI15 -v ./test/fault/  # one scenario
HALLPASS_FAULT_LOG=1 go test -tags fault ...                 # gateway logs on stderr
```

The suite needs Go only: no Docker, no root and no network access beyond 127.0.0.1. Tests that use
`chmod` skip when run as root.

## How faults are injected

| Technique | Used for |
|---|---|
| In-process gateway (`app.New` + `Serve`) in front of an in-process destination (`internal/testutil/sshtest`) | most scenarios |
| **Gateway child process killed with SIGKILL** (the test binary re-executes itself with `HALLPASS_FAULT_CHILD=1`). After the kill, an in-process gateway restarts on the same data directory and runs startup reconciliation. | FI-01..04, FI-22, FI-23 |
| Hook inside the child process: the recorder factory blocks forever (`block-open`) | FI-02 |
| External SQLite connection holding `BEGIN IMMEDIATE` (the write lock) | FI-04 (holds back the finalize transaction), FI-08, FI-09 |
| `PRAGMA max_page_count` on the writer connection (the database cannot grow, so writes fail with `SQLITE_FULL`) | FI-06 |
| Recorder wrapper (`faultFactory`) around the real HPREC1 recorder. It returns `ENOSPC`/`EIO` once a byte budget is spent, or delays every write. | FI-05, FI-07, FI-08 |
| TCP proxy in front of the destination or the gateway. It can blackhole traffic (holds bytes, no FIN or RST) or switch its upstream to a host with a different key. | FI-15, FI-16, agent-leg blackhole |
| Wall clock moved by an offset (`app.WithClock`) | FI-20, FI-21 |
| Writing grant state to the database directly (simulates a lost in-process event) | FI-21 |
| Byte flips, truncation, file swaps, deletion and stray files under `recordings/`, plus page corruption in `hallpass.db` | FI-10..13 |
| `storage.min_free_bytes` set above the free space (disk below reserve) and a read-only `recordings/` tree | FI-05, HP-REC-007 |
| Outbox provider that always fails (5xx, timeout, 429) | FI-18 |

## Catalog coverage

The Result column reflects the run on 2026-10-23 (Apple M1 Max, macOS 15.7.5, Go 1.27.3). A test that fails with
`FINDING:` is reporting a product defect. It is not a test bug. Those tests stay red until the product is fixed.

| ID | Test | Result |
|---|---|---|
| FI-01 | `TestFI01CrashDuringDecisions` | pass. 4 SIGKILLs during auto-approve request storms; every request ends up with all of decision, grant and session, or none of them |
| FI-02 | `TestFI02CrashBeforeSegmentCreated` | pass. The channel is interrupted, no segment is left open, and the destination is never reached. The crash point comes before the segment row exists, so "segment failed" does not apply. |
| FI-03 | `TestFI03CrashMidRecording` | pass. The segment is `interrupted` and its prefix authenticates. Measured loss was 81 ms of output (bound: 250 ms). |
| FI-04 | `TestFI04CrashBetweenRenameAndFinalize` | pass. Reconciliation marks the segment finalized, adds the chain entry, and verification passes. |
| FI-05 | `TestFI05FI07RecordingWriteFailureTerminates/FI-05_ENOSPC`, `TestFI05DiskReserveRefusesNewChannels` | **FAIL (finding)**. Exit 80 and the `failed` segment are correct, but unrecorded output is still forwarded (G-8). Refusal below the reserve passes. |
| FI-06 | `TestFI06SQLiteFull` | **FAIL (finding)**. The disk-full state is cleared by any successful write, including the readiness probe's empty transaction, so new channels are admitted. An established channel keeps working (pass). |
| FI-07 | `TestFI05FI07RecordingWriteFailureTerminates/FI-07_EIO_strict` | **FAIL (finding)**: same G-8 defect. "No fsync retry" cannot be observed at the recorder boundary. |
| FI-08 | `TestFI08SlowRecorderBackpressure`, `TestFI08StalledStorageTerminatesAfterBlockTimeout` | Backpressure passes (destination throttled, heap bounded). **FAIL (finding)**: with stalled storage the channel ends only after about 17 s, against a `block_timeout` of 1 s. |
| FI-09 | `TestFI09WriterContention`, `TestFI09GatewayAbsorbsShortContention` | pass. 5 bounded attempts, then `storage_busy`; health degrades after 30 s and recovers; a pinned reader only delays the checkpoint. |
| FI-10 | `TestFI10CorruptDatabaseRefusesStart` | Refusal with `ErrCorrupt` passes. **FAIL (finding)**: damage found when the database is opened produces no restore guidance. |
| FI-11 | `TestFI11FI12CorruptAndMissingSegments` | pass. Byte flip, truncation and cross-segment swap are reported `corrupt`, both live and after a restart. Replay stops at the last authentic frame. Frame reordering inside a segment is covered by `internal/recording/hprec` tamper tests. |
| FI-12 | same test | pass. `missing`, live and after a restart |
| FI-13 | `TestFI13OrphanSegmentQuarantined` | pass |
| FI-14 | `TestFI14KEKMissingOrWrong` | pass. Covers an unset or absent KEK in production, a wrong KEK (`ErrWrongKEK`), a group/world-readable KEK file, and a production config with the KEK inside `data_dir`. |
| FI-15 | `TestFI15DestinationBlackhole` | **FAIL (finding)**. The destination leg has no keepalive. |
| FI-16 | `TestFI16DestinationHostKeyChanged` | pass. Exit 88, an alert audit event, and the impostor never sees the credential. |
| FI-17 | `TestFI17AgentStopsReading` | Bounded memory and throttling pass. **FAIL (finding)**: the idle-terminated channel is never closed on the agent side. |
| FI-18 | `TestFI18ChatProviderOutage` | pass at the outbox layer: retry, retry, dead; attempts recorded; the request stays pending. Slack/Telegram client error classification is unit-tested in `internal/notify/*`. |
| FI-19 | (not duplicated here) | Covered by `internal/oidc` `TestOutage` and `TestJWKSRotation` with the mock IdP |
| FI-20 | `TestFI20ClockJumps`, `TestFI20BackwardJumpNearExpiry` | pass. A backward step never extends the grant; a forward step past expiry terminates the channel in under 1 s. Observation: after a backward step, expiry follows the wall clock. |
| FI-21 | `TestFI21LostRevocationEvent` | Lost event: terminated in about 1 s (pass). **FAIL (finding)**: when the event is lost after a backward wall-clock step, the revocation is not enforced. |
| FI-22 | `TestFI22SecondProcessSameDataDir` | pass, in-process and cross-process (flock) |
| FI-23 | `TestFI23RestartDuringPendingWait` | pass for both SIGTERM and SIGKILL |
| FI-24 | not feasible here | Simulating power loss needs a VM hard reset (QEMU) so that unsynced page cache is lost. SIGKILL keeps the page cache and is covered by FI-01..04. |

Extra scenarios outside the catalog:

| Test | Result |
|---|---|
| `TestReadOnlyRecordingsDirFailsClosed` | pass: refused before dialing, readiness fails, recovers |
| `TestAgentLegBlackhole` | pass: agent-leg keepalive releases the destination in 3 s |
| `TestAgentDisconnectReleasesDestination` | **FAIL (finding)**: an agent disconnect does not release a silent or unreachable destination session |
| `TestRevocationStorm` | pass: 16 concurrent revocations, lockdown and agent disable all terminate within about 160 ms |
| `TestQueueBytesBelowRecordSize` | **FAIL (finding)**: `recording.queue_bytes` below one record passes validation but kills every channel with large output |

## Writing new scenarios

- Use `newWorld(t)` to get a data directory, an agent key and a destination. Use `w.start(t, opts...)` for an
  in-process gateway. For a crash, call `w.setup(t, roles)`, then `w.spawn(t, hook)` and `c.kill()`, then
  `w.start(t)` to restart and reconcile.
- Assert the documented fail-closed outcome. If the product misses it, report it with
  `t.Errorf("FINDING: …")` and the requirement ID. Never weaken an assertion to make the suite green.
