# M2 — In-VM oracle verification kit

Turns the oracle from *designed* into *demonstrated*. Everything here runs
**without the agent or an API key** — we prove `verify_finding()` + the TTD
`reached_sink` detector against a target whose answer we already know, before
trusting the loop on top of it (one axis at a time).

**Fixture: the stack-overflow baseline.** We compile `bench/vuln.c` — a 16-byte
stack buffer + unbounded `strcpy`, **vendored** from the Bug Museum
`0_stack-overflow/variant-01-strcpy/src.c` so the build is self-contained on the
target VM (which has no BugMuseum checkout) — into `vuln.exe`. The **payload is
the command-line argument**
(`argv[1]`) — not a file. Under `/Od /GS-` (no stack cookie), a long-enough
argument overwrites the saved return address, so the `ret` faults with an
**access violation** at the controlled address. Self-authored / museum-sourced
⇒ **contaminated / plumbing only** (tag any Task built on it `contaminated=True`).

> **No page heap.** Page heap instruments the *heap*; it does nothing for a
> stack overflow. The oracle is called with `page_heap=False`. That apparatus
> returns for the `1_heap-overflow` / `2_use-after-free` museum variants.

Contents:
- `vuln.c` — the vendored fixture source (keep in sync with the museum original).
- `build.bat` — builds `vuln.exe` + `vuln.pdb` into `C:\lucent\sandbox` from
  `vuln.c` (`/Zi /Od /GS-`, x64-forced; pass a path as arg 1 to build a different
  source). The pdb is what lets cdb resolve `vuln!vuln` for the `reached_sink`
  milestone (BugMuseum's own build ships none).
- `archcheck.py` — PE-header dump; confirms the produced binary is x64 (the
  earlier lab pain was an arch mismatch → Win32 0n216).
- `verify_oracle.py` — the layered harness (preflight → oracle → detector → matrix).
- `diag.py` — decoupling diagnostic when a run misbehaves (isolates bug+cdb from TTD).

## Prerequisites (in the VM)

1. **Debugging Tools for Windows** → `cdb.exe` (Windows SDK; the path in
   `config.py` is the default). `gflags.exe` is **not** needed for this fixture.
2. **TTD** → `tttracer.exe` (in-box in System32, or install modern WinDbg) —
   only for the `reached_sink` milestone.
3. **Microsoft symbols** → internet access; create `C:\Symbols`.
4. **A C compiler** → MSVC Build Tools (`cl.exe`). `build.bat` forces the x64
   toolchain via `vcvars64`, so a plain cmd prompt works.
5. **Python 3.10+** and `pip install -r ..\src\requirements.txt` (just
   `anthropic` — imported transitively even though we never call it).
6. **Elevated shell** only for the TTD step (`tttracer`). The live AV verdict
   does not require admin.
7. **Snapshot the VM** first.

Confirm `config.py` (`CDB`, `TTTRACER`, `SYMPATH`, `SANDBOX_DIR`) matches the VM
before running.

## Run it

```bat
:: 1) build the fixture (plain cmd prompt is fine — build.bat sets up vcvars64)
bench\build.bat

:: 2) verify
python bench\verify_oracle.py
```

The harness passes the payloads as command-line **arguments** — `"A"*64` (crash)
and `"A"*8` (clean). There are no input files to stage.

## What success looks like

- **crash-64A:** `crashed=True`, an access-violation `exception_code`
  (`c0000005`), a `fault_address` of the controlled return address (e.g.
  `0x4141414141414141`), and a `bucket_id` from `!analyze`. `rip_controlled` is
  a heuristic — expect it to fire here, but do **not** report control as proven
  off it alone.
- **clean-8A:** `crashed=False` — **zero false positives** is the bar.
- **reached_sink:** call count ≥ 1 (execution reached `vuln!vuln`). `None` means
  no TTD trace (not elevated / TTD off), which is not the same as `0`.
- **confusion matrix:** `RESULT: PASS` (FP=0, FN=0).

## Two things this run resolves (and how to react)

1. **The real `BUCKET_ID`.** `EXPECTED_SIG` starts as `None`. Read the printed
   `bucket_id`, copy its stable substring into `EXPECTED_SIG` in
   `verify_oracle.py`, and rerun — now `matches_expected_bug` should be `True`.
   This is the identity check that makes the oracle "did it hit *the* bug," not
   "did anything crash."
2. **`av_type` for a return-address overwrite.** For a non-canonical controlled
   address cdb may classify the fault as an execute-AV, or print no
   `Attempt to …` line at all (in which case `av_type` is `None`). That is
   expected — `crashed` (AV present) + the `fault_address` are the primary
   signals for the stack case. If the classification differs from what
   `_parse_verdict` keys on, that's a real-output finding: fix the parser, don't
   fudge the fixture.

Anything that needed tweaking (tttracer flags, the `.run` filename, the `dx`
accessor spelling, the AV message shape) goes back into the code + the milestone
tracker — primary cdb/TTD output wins over anything the skeleton asserted.
