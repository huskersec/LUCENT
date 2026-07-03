# M2 — In-VM oracle runbook

> **Status (2026-07-03).** The **local in-VM oracle is DEMONSTRATED** on the
> stack fixture: `bench\build.bat` + `python bench\verify_oracle.py --no-ttd` returns
> `RESULT: PASS` (crash vs clean, zero FP/FN). That is the M2 bar and it is met.
>
> The **vSphere remote-trial** path (`src/trial.py`, §2–§5 below) is built and its
> cdb plumbing is fixed (symbol path via `-y`, not `.sympath`), but it still
> assumes the **old file-based input** (`_make_default_input` writes a byte file);
> the stack fixture takes its payload as **`argv[1]`**, so `trial.py` needs that
> one retarget before the remote trial runs end-to-end. Until then, §1 (local) is
> the authoritative M2 procedure.

Fixture: the stack-overflow baseline — `bench/vuln.c` (16-byte buffer + unbounded
`strcpy`) built to `vuln.exe` (+`vuln.pdb`). The payload is the command-line
**argument**; a long-enough arg overwrites the saved return address and the `ret`
faults with an access violation (`c0000005`). **No page heap** — that instruments
the heap and does nothing for a stack overflow.

---

## 1. Golden image + local validation (in the target VM)

Do this once, inside the disposable target Windows VM:

1. **Install the toolchain.** In an **elevated** PowerShell run `setup-vm.ps1`.
   It installs Debugging Tools for Windows (cdb), VS 2022 C++ Build Tools
   (cl.exe), and Python 3.11; sets `_NT_SYMBOL_PATH` and pre-populates symbols;
   installs Python deps; prints a pass/fail probe table; and pre-arms Full Page
   Heap for `vuln.exe` (harmless here — only matters for the later heap-class
   variants). Re-run it in a **fresh** elevated shell if any probe shows FAIL
   (winget PATH changes need a new session; that's what makes `pip install` land).

2. **Build the fixture.** Run `bench\build.bat` (it self-invokes `vcvars64`, so a
   plain prompt works). Produces `vuln.exe` + `vuln.pdb` in `C:\lucent\sandbox`
   and self-reports the PE machine type via `archcheck.py` (expect
   `0x8664 / PE32+`). The build clears prior outputs first, so `vuln.exe`
   existing == a good build.

3. **Validate the oracle locally.** This is the M2 verification:
   ```powershell
   python -u bench\verify_oracle.py --no-ttd
   ```
   Expect **crash-64A** `crashed=True` (`c0000005`, `av_type read_av`,
   `fault_address 0xffffffffffffffff` — the non-canonical-jump signature of the
   return-address hijack), **clean-8A** `crashed=False`, and
   **`RESULT: PASS`** (FP=0, FN=0). `--no-ttd` does a single symbol-free cdb
   live-launch per case (no `tttracer`, no admin needed for the verdict).
   - `$env:LUCENT_DEBUG=1` dumps the raw cdb text the parser reads.
   - To also capture the `!analyze` `BUCKET_ID` (for `EXPECTED_SIG`, the identity
     check), run once **without** `--no-ttd`-style restrictions as
     `$env:LUCENT_ANALYZE=1; $env:LUCENT_ORACLE_TIMEOUT=600` — that opts into
     `kb`/`!analyze -v`, which need the symbol server reachable.

4. **Snapshot.** Clear any `LUCENT_*` env vars, settle the box, then snapshot the
   VM as **`golden`**. A **powered-on, with-memory** snapshot reverts fastest.
   Note: if the LUCENT repo lives on a host-mounted share, it is **not** captured
   by the snapshot — copy it to a local disk path if you want it baked in.

> The `--no-ttd` path is symbol-free by design (symbol path is a local `-y` dir,
> and the verdict comes from `.exr -1`, not `!analyze`). It does not depend on
> reaching `msdl.microsoft.com`, so it works on an offline VM.

---

## 2. Service account (vCenter) — for the remote-trial path

Create the least-privilege `serviceaccount` role and the non-propagating,
target-VM-only permission as described in
[`vcenter-least-privilege.md`](./vcenter-least-privilege.md).

## 3. Orchestrator env (dev box)

On the orchestrator/dev machine, install the client deps and export the
environment. Keep all secrets in the environment — never in code.

```bash
pip install pyvmomi requests
```

```bash
export VC_HOST=vcenter.example.local
export VC_USER='serviceaccount@vsphere.local'
export VC_PASSWORD='...'
export VC_INSECURE=1                 # only for a self-signed lab cert
export TARGET_GUEST_USER='lucent'
export TARGET_GUEST_PASSWORD='...'
```

The target VM UUID is read from `vm-uuid.txt` at the repo root (override with
`TARGET_VM_UUID`).

## 4. Validate (read-only)

Confirm connectivity and that the UUID resolves to the right VM **before** doing
anything destructive:

```bash
python src\vsphere_target.py
```

This prints the resolved VM name, both UUIDs, the current power state, and the
snapshot list — and takes **no** destructive action.

## 5. Remote trial (`src/trial.py`) — pending input retarget

```bash
python src\trial.py
```

This reverts to **`golden`**, stages the target + input into the guest sandbox,
runs cdb triage in the guest (symbol path via `-y`, script parsed by
`oracle._parse_verdict`), parses the verdict, and reverts again (even on failure).

**Remaining gap:** `trial.py` still pushes a byte **file** as the input
(`_make_default_input`) and passes its guest path as the target arg — the model
for the old file-reading heap fixture. For the stack fixture the payload must be
the literal `argv[1]` string (e.g. `"A"*64`). Retarget `_make_default_input` /
the input plumbing to pass the payload as an argument, and update
`DEFAULT_TARGET`/`DEFAULT_IMAGE_NAME` from `target.exe` to `vuln.exe`, before this
runs end-to-end.

**Expected verdict once retargeted:** a return-address **access violation**
(`c0000005`) at `vuln!vuln` — not a heap write-AV. Artifacts (cdb log, any TTD
`.run`) land in `./trials/<timestamp>/`. TTD is off by default (`--record-ttd`
to enable).

## Guardrail note

The fixture is **known / self-authored (vendored from the Bug Museum)**, so every
run on it is **plumbing validation only** — it proves the loop drives the tools
and the oracle classifies a known crash correctly. It is **not** a capability
claim (contaminated; tag any `Task` built on it `contaminated=True`).
