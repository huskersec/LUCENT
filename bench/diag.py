#!/usr/bin/env python3
"""
LUCENT — M2 trace-production diagnostic (stack-overflow fixture).

When verify_oracle.py reports something unexpected (crashed=False, or no TTD
trace found), this decouples the unknowns and prints raw evidence so we're not
blind to what cdb/tttracer actually saw. Run from an ELEVATED shell in the VM:

    python bench\\diag.py

FIXTURE: vuln.exe (stack overflow, /Od /GS-). The PAYLOAD IS argv[1] — a long
string overruns the 16-byte buffer and clobbers the saved return address, so
`ret` faults with an ACCESS VIOLATION. No page heap involved.

It answers three questions:
  PHASE 1 — does the bug actually fault, with NO TTD involved?
            (verify_finding(record_ttd=False) + a raw cdb session dump)
  PHASE 2 — what is tttracer's REAL syntax on this box? (its own -? help)
  PHASE 3 — which tttracer invocation actually drops a .run, and WHERE?
            (tries variants, captures exit/stdout/stderr, lists every file)
"""
import glob
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-lucent-oracle-only-unused")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
try:
    from lucent import config
    from lucent.oracle import verify_finding
except ModuleNotFoundError:
    from src import config
    from src.oracle import verify_finding

SANDBOX    = config.SANDBOX_DIR
TARGET_EXE = os.path.join(SANDBOX, "vuln.exe")
IMAGE      = "vuln.exe"
CRASH_ARG  = "A" * 64               # overruns buf[16] -> return-address AV


def hr(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def run(argv, timeout=None):
    print("$", " ".join(f'"{a}"' if " " in a else a for a in argv))
    # Capture to a FILE, not a pipe: when the target CRASHES under cdb/tttracer,
    # the suspended child / WerFault can inherit an output PIPE and hold it open,
    # so subprocess blocks to the timeout even after the tool is done (the trap
    # fixed in oracle._run_cdb). A file waits only for the tool itself to exit;
    # stdin=DEVNULL so cdb can never block on an interactive prompt.
    fd, path = tempfile.mkstemp(prefix="lucent_diag_", suffix=".txt")
    timed_out = False
    try:
        with os.fdopen(fd, "wb") as f:
            try:
                subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL,
                               timeout=timeout or config.ORACLE_TIMEOUT)
            except subprocess.TimeoutExpired:
                timed_out = True
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out = f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    print("  TIMEOUT (partial output below)" if timed_out else "  exit: done")
    if out.strip():
        print("  --- output (stdout+stderr) ---\n" + out[-4000:])
    return out


def main():
    print(f"[info] target {TARGET_EXE}  arg={CRASH_ARG[:8]}...({len(CRASH_ARG)} bytes)")

    # ---- PHASE 1: does it fault at all, with NO TTD? -------------------------
    hr("PHASE 1 — live oracle, record_ttd=False (isolates bug+cdb from TTD)")
    v = verify_finding({"target_cmd": [TARGET_EXE], "trigger_path": CRASH_ARG,
                        "image_name": IMAGE, "page_heap": False},
                       record_ttd=False)
    for k, val in v.items():
        print(f"  {k:21} {hex(val) if k == 'fault_address' and isinstance(val, int) else val}")
    print("  -> if crashed=True/AV here, the bug is fine and only TTD is broken.")
    print("  -> if crashed=False here, the crash path is the problem (see 1b).")

    hr("PHASE 1b — RAW cdb live session (full output; what cdb actually sees)")
    # Symbol path via -y, NOT `.sympath` in the script (that swallows the rest of
    # the line — `;` separates path elements there, not commands). kb + !analyze
    # force-load symbols, so this deliberate full-triage dump wants the symbol
    # server reachable; drop them if you only need to confirm the fault fires.
    script = ("sxe av; g; .echo ===FAULT===; "
              ".ecxr; r; kb; !analyze -v; .echo ===END===; q")
    run([config.CDB, "-y", config.SYMPATH, "-g", "-G", "-c", script,
         TARGET_EXE, CRASH_ARG])

    # ---- PHASE 2: the authoritative syntax, from tttracer itself -------------
    hr("PHASE 2 — tttracer -? (on-box help == primary source for the real flags)")
    run([config.TTTRACER, "-?"], timeout=30)

    # ---- PHASE 3: which invocation produces a .run, and where? ---------------
    hr("PHASE 3 — tttracer invocation variants (capture output + list ALL files)")
    variants = [
        ("current (no -launch)", ["-out", "{d}", "-dumpFull", TARGET_EXE, CRASH_ARG]),
        ("with -launch",         ["-out", "{d}", "-dumpFull", "-launch", TARGET_EXE, CRASH_ARG]),
        ("-launch, no -dumpFull", ["-out", "{d}", "-launch", TARGET_EXE, CRASH_ARG]),
    ]
    for name, tmpl in variants:
        d = tempfile.mkdtemp(prefix="ttdiag_")
        print("\n" + "-" * 50 + f"\nvariant: {name}\n" + "-" * 50)
        run([config.TTTRACER] + [a.replace("{d}", d) for a in tmpl])
        in_dir = sorted(os.listdir(d)) if os.path.isdir(d) else []
        runs_in = glob.glob(os.path.join(d, "*.run"))
        parent = os.path.dirname(d)
        runs_beside = glob.glob(os.path.join(parent, os.path.basename(d) + "*.run"))
        print(f"  out dir: {d}")
        print(f"  files IN out dir:    {in_dir}")
        print(f"  *.run IN out dir:    {runs_in}      <-- find_trace() looks here")
        print(f"  *.run BESIDE out dir:{runs_beside}")

    hr("DONE — paste this whole output back.")


if __name__ == "__main__":
    main()
