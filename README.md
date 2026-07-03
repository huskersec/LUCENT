# LUCENT

**Making opaque binaries legible** — an agent-driven vulnerability-research system that doubles as a capability-measurement harness for autonomous binary analysis on Windows.

LUCENT drives an LLM agent to reverse-engineer and patch-diff compiled Windows targets for memory-safety bugs, wrapped in an evaluation layer that measures *how well* it does — producing defensible statements of the form "harness X solves bug class Y at rate Z for cost C." The core bet: **binary patch-diffing is the closed-source analog of reading the commit that introduced a fix.**

## Architecture

Three layers — the agent **acts**, the oracle **judges**, the scoring layer **measures**:

- **`src/agent.py`** — a minimal ReAct tool-use loop. The `run` tool is the single swap point for the toolchain (Linux/ASan for the learning phase → the Windows debugger stack for binary targets).
- **`src/oracle.py`** — the binary crash oracle (`verify_finding`). Launches a target under `cdb`, catches the access violation, and returns an unfakeable structured verdict (crash type, fault address, `!analyze` bucket). The closed-source answer to source + AddressSanitizer.
- **`src/scoring.py`** — the eval layer: `Task`, multi-seed trials, pass@k vs. solve-rate, milestone partial-credit, append-only run records.

Supporting modules: `src/ttd.py` (Time Travel Debugging replay seam for progress detectors), `src/vsphere_target.py` (UUID-pinned disposable-VM control), `src/trial.py` (revert → run → triage → revert), and `m2/` (the in-VM oracle verification kit).

## Current status — 2026-07-03

**M2 (hard oracle wired & verified): ✅ demonstrated (local).**

The oracle is proven against a known-vulnerable fixture — the stack-overflow baseline `m2/vuln.c` (a 16-byte stack buffer + unbounded `strcpy`, vendored from the Bug Museum), built to `vuln.exe`. The payload is the command-line argument; a long-enough arg overwrites the saved return address and the `ret` faults with an access violation the oracle catches and classifies, with **zero false positives/negatives** on known crash-vs-clean inputs.

Open next: the `EXPECTED_SIG` bucket-identity check, the TTD `reached_sink` progress rung, and the full MCP-backed tool layer (M3). See `FRT-Lab-Milestone-Tracker.md` for the milestone ladder and `docs/M2-runbook.md` for the in-VM procedure.

## Initial testing

Inside the disposable target Windows VM (Debugging Tools for Windows + MSVC Build Tools + Python 3.10+; `setup-vm.ps1` bootstraps the toolchain):

```powershell
# 1) build the fixture -> vuln.exe (+ vuln.pdb) into C:\lucent\sandbox
m2\build.bat

# 2) verify the oracle (symbol-free path: no admin, no network needed)
python -u m2\verify_oracle.py --no-ttd
```

Expected result (condensed):

```
crash-64A  expect_crash=True    crashed=True   c0000005   read_av   fault_address 0xffffffffffffffff
clean-8A   expect_crash=False   crashed=False
RESULT: PASS   (FP=0, FN=0)
```

The `read_av` at `0xffffffffffffffff` is the signature of a jump to a non-canonical address — i.e. the return address was overwritten (`0x4141…`) and the `ret` hijacked. Set `LUCENT_DEBUG=1` to dump the raw `cdb` triage the verdict is parsed from.

## Scope / contamination

The bug-museum fixture is **self-authored / public-pattern**, so any run on it is **plumbing validation only** — it proves the loop drives the tools and the oracle classifies a known crash correctly; it is **not** a discovery-capability claim. Capability numbers are reserved for targets whose *analysis* postdates the model's training cutoff (freshly patch-diffed Patch Tuesday bugs), keyed by `(target_sha256, os_version)` with a versioned harness.

## Repository layout

```
src/         agent · oracle · scoring · ttd · vsphere_target · trial   (the LUCENT package)
m2/          in-VM oracle verification kit: vuln.c, build.bat, verify_oracle.py, diag.py, archcheck.py
docs/        M2-runbook.md
setup-vm.ps1 golden-image toolchain bootstrap (run elevated, in the VM)
```
