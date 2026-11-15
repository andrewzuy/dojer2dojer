# MEMORY — persistent rules for this project

Long-lived rules and incident memories for the `p2p-tunnel` Python port.
Read this **before doing any work** on the project. `PLAN.md` is the plan,
`PROGRESS.md` is the log; this file is the standing ground rules.

---

## Rule 1 (ABSOLUTE) — every command is time-limited to 5 minutes

**NEVER execute a command — tests, builds, scripts, anything — without an
execution-time restriction of at most 5 minutes (300 s).**

How to comply:

- Always invoke shell commands with a 300 s timeout: the harness `timeout`
  parameter = 300, or wrap the command: `timeout 300 <command>`.
- No exceptions, no "just this once" long runs. If it might run longer
  than 5 minutes, it must be limited.
- If a full test suite or build is expected to take longer than 5 minutes,
  split it into smaller batches (e.g. per-module
  `python -m unittest tests.test_stun`), each batch under 5 minutes, or ask
  the operator first.
- Long-running/interactive programs (the tunnel itself, mock bot servers)
  must be started under `timeout 300 ...` or explicitly killed afterwards;
  never leave a process running unbounded.
- A timed-out run is a result, not a failure of diligence: report the
  timeout, narrow the scope, and re-run the batch.

**Why (incident, 2026-11-15):** an unrestricted
`python -m unittest discover -s tests` hung on a deadlocked test
(the known-bugged, untracked `tests/test_tunnel.py` draft with the
self-looping `_MemPipe`) and ran for **5 h 58 m 13 s**. The operator
banned unrestricted command execution outright. This rule is stated
here, in `PLAN.md`, and in the 2026-11-15 entry of `PROGRESS.md`.

---

(Add new standing rules below this line, numbered in sequence.)
