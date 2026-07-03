# FRT Portfolio-Round Lab Milestone Tracker

**Purpose:** Backward-planned milestone ladder for the autonomous Claude agentic VR home lab, scoped to have a *defensible, demonstrable-under-questioning* artifact in hand by the FRT portfolio deep-dive round. Living document — update status, dates, and notes as work progresses.

**Strategy in one line:** Apply now to start the clock; use the interval before the portfolio round to push the agentic dimension from "designed" to "demonstrable." The offer hinges on showing the agentic-AI dimension is *actively being reached toward* — a momentum-and-direction bar, not a completion bar.

---

## ⏱ Current status — 2026-07-03 · READ THIS FIRST

**Active milestone:** **M2** (hard oracle wired & verified) — ✅ *LOCAL oracle DEMONSTRATED on the stack fixture (2026-07-03). `verify_oracle.py --no-ttd` returns **RESULT: PASS** (crash-64A crashed=True / c0000005 / read_av / fault 0xffffffffffffffff; clean-8A crashed=False; FP=0 FN=0).* Ready to bake the `golden` snapshot.

**2026-07-03 — M2 local oracle green after a run of infrastructure bugs (all fixed in code; not oracle-logic bugs).** The crash verdict on `vuln.exe` (stack overflow, argv payload, return-address hijack → non-canonical `ret`, reported as `c0000005` read-AV at `0xffffffffffffffff`) now classifies crash-vs-clean with zero errors. The fixes, in the order they were peeled back:
1. **`build.bat` self-clobber** — the final `echo [build] OK -> %OUT%\vuln.exe` had `->`, which cmd read as a redirect that overwrote the freshly-linked exe with the status text ("not a valid PE" / "unsupported 16-bit application"). This also explains the *old* `target.exe` "not a PE" saga — same `->` bug, misattributed to arch/toolchain. Now hardened (clears prior outputs, fails loudly, no `->`).
2. **subprocess PIPE deadlock on crash** — `verify_finding` captured cdb via `capture_output=True`; on a crash the suspended target / WerFault inherits the pipe write-handle, so `communicate()` never sees EOF and hangs to the timeout (the clean run exits and closes the pipe, so ONLY crashes hung). Fixed: capture cdb to a temp FILE + `stdin=DEVNULL`; tttracer record → DEVNULL.
3. **`.sympath` swallowed the script** — `.sympath X; sxe av; g; ...` makes `.sympath` eat the whole line (`;` separates path elements there, not commands), so the crash script never ran. Fixed: symbol path via the `-y` cdb flag; same fix in `ttd.py`.
4. **`!analyze -v` / `kb` symbol-server stalls** — force-load symbols from msdl; on a slow/offline VM they hang. Made opt-in via `LUCENT_ANALYZE=1`; default verdict is symbol-free (`.exr -1` + `.ecxr`/`r`) with a local `-y` symbol path. New env overrides: `LUCENT_ORACLE_TIMEOUT`, `LUCENT_SYMPATH`, `LUCENT_DEBUG` (dumps raw cdb), `LUCENT_ANALYZE`.

**⏭ Next:** (a) snapshot `golden` once the pre-snapshot checks pass; (b) optional `LUCENT_ANALYZE=1` run to capture the real `BUCKET_ID` → set `EXPECTED_SIG` for the identity check; (c) fix the host→guest file-sync workflow (stale copies on the VM cost several debugging rounds); (d) then climb the ladder (`/O2 /GS` cookie fail-fast) and/or retarget the deferred vSphere `trial.py`.

---

**Restart context (2026-07-02):** Reapproached M2 against a simpler fixture after a tooling mix-up (Dispatch vs Code) muddied the heap-fixture work.

**🔀 PIVOT — new baseline is a STACK overflow, not the heap fixture.** We are reapproaching M2 against an *easier, more legible* bug and climbing a ladder from there. The old self-authored heap fixture (`m2/target.c`, 64B `malloc` + `memcpy`, file input, Full Page Heap, `parse_record`) is retired. The new baseline is the **Bug Museum `0_stack-overflow/variant-01-strcpy/src.c`** (16-byte stack buffer + unbounded `strcpy`), built by LUCENT as **`vuln.exe` + `vuln.pdb`** with `/Zi /Od /GS-`.

Three things this changes about the oracle (all now reflected in code):
1. **Input is the command-line argument (`argv[1]`), not a file.** No more `trigger.bin`/`clean.bin`; the payload is a string (`"A"*64` crash / `"A"*8` clean).
2. **No page heap.** Page heap instruments the *heap*; it does nothing for a stack overflow. `verify_finding` gained a **`page_heap` toggle (default False)**; it returns for the heap/UAF variants. The crash signal is now a **return-address-overwrite access violation** on `ret` (caught by the existing `sxe av`), not a guard-page `write_av`.
3. **`reached_sink` survives; `corrupted_object` is heap-only.** `reached_sink("vuln!vuln")` still checks reach off the TTD trace (needs the pdb `build.bat` now emits). `corrupted_object()` keys on the page-heap guard-page address and does *not* map to the stack — deferred (documented in `scoring.py`).

**🪜 The ladder (work our way up, one axis at a time):**
`vuln.exe /Od /GS-` (return-address AV — **here now**) → `/O2 /GS-` (same bug, optimized; buffer may DCE) → `/O2 /GS` (stack cookie → `STATUS_STACK_BUFFER_OVERRUN` fail-fast, *not* an AV — needs a new catch) → heap-overflow / UAF / double-free museum variants (page heap comes back on).

**🎯 Scope of this pass — LOCAL-FIRST.** Retarget only the `m2/` kit + `src/oracle.py` and prove a real AV verdict on `vuln.exe` in the VM. The **vSphere remote-trial path (`src/trial.py`, `docs/M2-runbook.md`) is deferred** and still points at the old heap fixture (runbook now carries a banner saying so). `src/vsphere_target.py` is target-agnostic and untouched.

**✅ Done this pass (code retargeted; UNVERIFIED against live cdb/TTD):**
- `m2/build.bat` → compiles the museum `src.c` to `vuln.exe`+`vuln.pdb` (`/Zi /Od /GS-`, x64-forced).
- `src/oracle.py` → `page_heap` toggle (off for stack); page-heap calls gated; `fault_address`/`av_type` comments now cover the stack case.
- `m2/verify_oracle.py` → arg payloads, `vuln!vuln` sink, guard-page write-calibration removed, confusion matrix kept.
- `m2/diag.py` → page heap dropped, phase-1 retargeted to the return-address AV.
- `m2/archcheck.py`, `m2/README.md`, `setup-vm.ps1` (page-heap step reframed as heap-class pre-arm on `vuln.exe`), `src/handoff.md`, `src/scoring.py`, `src/agent.py` → retargeted / annotated.
- Deleted `m2/target.c` and stale `__pycache__/`.

**⏭ Next actions (in order):**
1. In the VM: `m2\build.bat` → confirm `archcheck` prints `machine: 0x8664 / PE32+`, and `vuln.exe`+`vuln.pdb` land in the sandbox.
2. `python m2\verify_oracle.py` → expect **crash-64A `crashed=True`** (AV, `exception_code c0000005`, `fault_address` ≈ `0x4141414141414141`), **clean-8A `crashed=False`**, confusion matrix **PASS**.
3. Capture the real `!analyze BUCKET_ID` → set `EXPECTED_SIG` → rerun for `matches_expected_bug=True`.
4. Confirm the return-address AV's `av_type` classification (may be exec-AV or `None`) and tune `_parse_verdict` to the *real* cdb message — do not fudge the fixture.
5. Elevated: exercise the TTD record→replay leg so `reached_sink` returns ≥1.
6. Only then: climb to `/GS`, and separately retarget `trial.py` + the runbook off the heap fixture.

**🟡 Prior facts still standing:** OS is **x64/AMD64**; `tttracer` does **not** need `-launch`; the trace lands as `*NN.run` in the `-out` dir (`find_trace`'s glob is correct).

---

## Planning assumptions (verify / adjust)

- **Loop timeline:** Portfolio deep-dive lands ~8–12 weeks after applying (recruiter screen ~2 weeks out → technical rounds → portfolio deep-dive later in sequence).
- **Daily work:** A real focused block most days, not a full workday.
- **Defensible floor by ~Week 5** (M3) in case the loop compresses; strong artifacts by ~Week 9 (M5).
- **Application status:** Applying now, resume mods first (agentic lab listed as *in-progress / active research*, never as shipped capability).

> ⚠️ If either timeline assumption is wrong, re-baseline the whole ladder against the real recruiter-screen date.

---

## The target set (what the portfolio round actually rewards)

The differentiator is **not** "my agent found a bug." It's: *I built a measurement harness that produces a defensible capability verdict — hard oracle, multi-seed, contamination-controlled — with honest failure analysis.* That is the researcher signal that separates you from candidates who wired up an agent framework over a weekend.

Priority order when time is tight:
1. **Oracle rigor** (M2) — never cut.
2. **Closed loop + one walkable trajectory** (M3, the floor).
3. **One clean capability measurement on a fresh diff** (M4) — a *failure* here is still a valid artifact.
4. **Eval report / narrative** (M5) — the centerpiece is a document, not code.

---

## Milestone ladder

### M1 — Loop closes, one tool wired
**Target: Weeks 1–2** · **Status: ☐ Not started**

- [ ] ReAct skeleton on the Anthropic SDK
- [ ] Single tool dispatched end-to-end (start with GhidraMCP or the oracle path)
- [ ] Run against the bug museum (contaminated — plumbing only, NOT a capability claim)
- [ ] **Artifact:** trajectory log showing the loop call a tool and act on structured output

*Goal: prove the orchestration closes before trusting it with anything.*

**Notes / blockers:**
_(update here)_

---

### M2 — Hard oracle wired and verified ★ highest-leverage piece
**Target: Weeks 2–3** · **Status: ✅ Local oracle DEMONSTRATED (2026-07-03) — crash/clean verdict PASS on the stack fixture. Remaining: BUCKET_ID/`EXPECTED_SIG` + the TTD `reached_sink` leg. (see ⏱ Current status up top)**

- [x] cdb (+ optional page heap for heap-class) producing a binary crash verdict — **stack baseline: return-address AV via `sxe av`, `page_heap=False`** *(2026-07-03)*
- [ ] `!analyze` bucket comparison integrated (`EXPECTED_SIG` set from the real `BUCKET_ID`) — pending one `LUCENT_ANALYZE=1` run with the symbol server reachable
- [x] Verified against known ground truth: crash-64A (crash) + clean-8A (clean) *(2026-07-03)*
- [x] Confirm correct classification with **zero false positives** *(FP=0, FN=0, 2026-07-03)*
- [x] **Artifact:** confusion-matrix-style verdict table on known inputs *(verify_oracle.py `RESULT: PASS`)*
- [ ] TTD record→replay leg green so `reached_sink("vuln!vuln")` ≥ 1

*Goal: this is the closed-source analog of source+ASan. Every downstream capability claim rests on this oracle being trustworthy. An untrustworthy oracle invalidates everything above it — and an interviewer will find that crack in ~two questions.*

**Notes / blockers:**
- **2026-07-03 — local oracle GREEN.** Full root-cause history + fixes are in the ⏱ Current status block up top. Crash/clean verdict is demonstrated (`verify_oracle.py --no-ttd` → `RESULT: PASS`). The earlier **heap-era blockers are archived, not active** — and several were misdiagnosed at the time:
  - *"target.exe not a valid PE" / "wrong architecture" / Win32 0n216* — red herrings. The real cause was `build.bat`'s `->` **self-clobber** (the status `echo` redirected over the freshly-linked exe), compounded by **stale copies** on the VM. Not an arch or page-heap problem. Fixed in the hardened `build.bat` (+ `archcheck.py` remains a useful PE sanity check).
  - *tttracer `-launch` / TTD trace-production / nested cdb-debugging-tttracer* — belong to the TTD `reached_sink` leg (still open, below), not the core verdict, which is now symbol-free and TTD-free.
- **Still open (NOT blocking the milestone):**
  1. **EXPECTED_SIG / bucket identity.** One `LUCENT_ANALYZE=1` run with the symbol server reachable → capture the real `BUCKET_ID` → set `EXPECTED_SIG` so `matches_expected_bug` works (turns "did it crash" into "did it hit *this* bug").
  2. **TTD `reached_sink` leg.** record (`tttracer`) → replay (`cdb -z`) → `dx @$cursession.TTD.Calls(...)` is still UNVERIFIED against real output (see `ttd.py` header). `verify_oracle.py` *without* `--no-ttd` exercises it — expect bring-up work; not a snapshot blocker.
  3. **Two overlapping harnesses** — `m2/verify_oracle.py` (local) vs `src/trial.py` (remote). Same cdb-script/verdict logic; consolidate the shared bits so they can't drift. `trial.py` also still needs the file→`argv` input retarget (runbook §5).
- **Bug classes found during bring-up, now swept across ALL cdb-driving code** (`oracle.py`, `ttd.py`, `diag.py`, `trial.py`): (a) `subprocess` **pipe deadlock** on crash → capture cdb to a FILE + `stdin=DEVNULL`; (b) **`.sympath` swallowing the script** → symbol path via the `-y` flag; (c) **`kb`/`!analyze` symbol-server stalls** → opt-in `LUCENT_ANALYZE`, default verdict from `.exr -1`; (d) `build.bat` `->` self-clobber. New env knobs: `LUCENT_ORACLE_TIMEOUT`, `LUCENT_SYMPATH`, `LUCENT_DEBUG`, `LUCENT_ANALYZE`.
- **Resolved:** the clean-run `=== FAULT ===` fragility is gone — cdb ends the session at clean process-exit *before* the post-`g` echo runs, and `crashed` also requires `ExceptionAddress`, so a clean run cannot be misread as a crash.

---

### M3 — Full tool layer integrated → **DEFENSIBLE FLOOR**
**Target: Weeks 3–5** · **Status: ☐ Not started**

- [ ] WinDbg-MCP dispatchable
- [ ] GhidraMCP dispatchable
- [ ] BinDiff-MCP (or custom ghidriff MCP) dispatchable
- [ ] Agent can: ingest a diff → navigate to changed function → reason about it → deliver input → get an oracle verdict
- [ ] Run on a target where the answer is **already known** (debugging the agent, not the bug)
- [ ] **Artifact:** one clean end-to-end trajectory, walkable turn by turn

> **★ THIS IS THE FLOOR. Must have this before the portfolio round even if everything else slips.** A closed loop + trustworthy oracle + one walkable trajectory is already a credible "actively reaching toward" story.

**Notes / blockers:**
_(update here)_

---

### M4 — Clean capability measurement on a fresh diff
**Target: Weeks 5–7** · **Status: ☐ Not started**

- [ ] Select a patch diff NOT hand-solved (uncontaminated → real capability measurement)
- [ ] Blind-first: form independent hypothesis before consulting any public PoC/writeup
- [ ] Multi-seed runs
- [ ] Append-only run records
- [ ] Scored results

> **A failure here is still a valid artifact.** e.g. "reached the changed function in 4/5 seeds but never constructed a triggering input because BinDiff surfaced the wrong anchor" — exactly the rigorous, honest result FRT respects more than a lucky success.

**Notes / blockers:**
- **2026-06-22 — Phase-2 milestone detectors implemented (skeleton, UNVERIFIED).** The reach → trigger ladder is now scaffolded in code: `reached_sink(symbol)` and `corrupted_object(addr)` in `scoring.py` (now per-target factory functions, wired for `Task.milestones`), plus a new `ttd.py` replay seam that opens the trace's `.run` under cdb and queries the TTD data model (`TTD.Calls(...).Count`, `TTD.Memory(...,"w").Count`). Exported from the package. Byte-compiles; the `dx … .Count` parsing is unit-checked. The cdb/TTD command strings are written against documented behavior but **not yet run end-to-end — verify against real output in the VM.**
- **2026-07-03 (update):** detector applicability clarified for the stack fixture. `reached_sink("vuln!vuln")` applies (needs the TTD leg green + `vuln.pdb`, which `build.bat` emits). **`corrupted_object()` is HEAP-only** — it keys on the page-heap guard-page fault address, which doesn't exist on the stack (there the fault address is the controlled return address, never a written-to object); it's documented as N/A in `scoring.py` and a stack-aware 'trigger' rung is deferred. TTD data-model query strings (`TTD.Calls`/`TTD.Memory`) remain UNVERIFIED against real output.
- *Not started:* the rest of M4 (target selection, blind-first hypothesis, multi-seed runs on a fresh diff). Detector work is enabling infrastructure, not an M4 capability claim.

---

### M5 — Eval report + narrative (portfolio centerpiece)
**Target: Weeks 7–9** · **Status: ☐ Not started**

This is a **document**, not code:
- [ ] Methodology
- [ ] Contamination controls (museum/Sync Breeze for plumbing only; fresh diffs for capability claims)
- [ ] Results across seeds
- [ ] Failure taxonomy
- [ ] Bottleneck-tool analysis (which tool was the limiting factor)
- [ ] Defensive-framing argument: capability characterization of the most widely deployed closed-source attack surface
- [ ] Honest scoping of what it can't do
- [ ] **Artifact:** the report that reads as research, not tooling

**Notes / blockers:**
_(update here)_

---

### M6 — Polish + rehearsal buffer
**Target: Weeks 9–10** · **Status: ☐ Not started**

- [ ] Clean up the live-walkthrough trajectory
- [ ] Pre-build answers to probing questions on the agentic/measurement axis
- [ ] Absorb integration slippage (it *will* happen)

**Notes / blockers:**
_(update here)_

---

## Where the timeline will actually bleed

- Agent reasoning is the **easy** part — Claude carries it.
- The time sink is **integration:** MCP bridges over DbgEng COM, KDNET, and TTD are fiddly. Slippage concentrates in **M2 (oracle plumbing)** and **M3 (tool layer)**.
- Don't let a polished agent loop trick you into thinking you're ahead while the oracle is still flaky.

**If you must cut scope:** cut M4's seed count and M5's breadth. **Never cut oracle rigor (M2).**

---

## Fallback branch — "if I'm at Week 5 and the oracle's still flaky"

The story you present is gated on what's actually trustworthy, not on what's polished:

- **Floor intact (M3 done, oracle solid):** Present the closed loop + one walkable known-target trajectory + the *designed* measurement methodology. Frame M4/M5 as in-flight. This is a fully credible "actively reaching toward" story on its own.
- **Oracle still flaky at Week 5:** Do **not** present capability claims. Present the architecture, the oracle-verification methodology, and the honest statement that you're hardening the verdict layer before trusting any capability number. This *is* the rigor signal — refusing to claim capability on an unverified oracle is itself the researcher discipline FRT screens for.
- **Loop compressed to ~6 weeks total:** You'll be at M3–M4. Still defensible. Lead with the floor; present M4 as preliminary/single-seed if that's where it sits.

> Never be caught without a story. The floor (M3) + honest scoping is always a valid presentation.

---

## Discipline guardrails (keep faith with your own methodology)

- **One axis at a time** — don't combine new bug class + new tool + new target in one step.
- **Known targets while debugging the agent; fresh diffs only for capability claims.**
- **Blind-first, validate-after** on the fresh diff (M4).
- **Contamination is binary:** anything hand-solved or museum-sourced is plumbing-only and cannot back a capability claim.
- **Primary-source discipline:** the trajectory logs and oracle verdicts are ground truth, not the agent's self-narration.

---

## Net timeline

| Outcome | Weeks of daily focused work |
|---|---|
| Defensible floor (M3) | ~5 |
| Strong version (M5) | ~9–10 |

Fits comfortably inside an 8–12 week loop. Even a compressed 6-week loop leaves you at M3–M4 — still defensible.

---

## Resume framing reminder

The agentic lab goes on the resume as **in-progress / active independent research** — e.g. "Building an autonomous vulnerability-research agent" framed as current research. Accurate *and* exactly the signal FRT wants. Overclaiming it as done is the only way to turn the asset into a liability.

---

*Living document. Update milestone status, target dates against the real recruiter-screen date, and notes/blockers as you go.*
