#!/usr/bin/env python3
"""
LUCENT — M2 oracle / TTD verification harness (standalone; no agent, no API key).

Exercises verify_finding() + the TTD replay seam against a KNOWN-vulnerable
target, so we verify the oracle BEFORE wiring the agent on top (one axis at a
time). The cdb/TTD command strings this drives are the ones still marked
"unverified" in the code — this run is what verifies them.

FIXTURE: the stack-overflow baseline (Bug Museum variant-01-strcpy), built by
m2/build.bat as vuln.exe (+ vuln.pdb) with /Od /GS-. The bug is a 16-byte stack
buffer + unbounded strcpy; the PAYLOAD IS THE COMMAND-LINE ARGUMENT (argv[1]),
not a file. A long-enough arg overwrites the saved return address, so the `ret`
faults with an access violation the oracle's `sxe av` catches.

  NO page heap here — page heap instruments the heap and does nothing for a
  stack overflow (page_heap=False). It returns for the heap/UAF variants.

Layers:
  1. preflight — tool paths + target exist; are we elevated (needed for TTD)?
  2. oracle    — verdict per input (crashed / av_type / fault_address / bucket)
  3. detectors — reached_sink (did we call vuln!vuln, read off the TTD trace)
  4. matrix    — predicted-crash vs known-crash; expect zero misclassifications

Run from an ELEVATED shell if recording TTD — tttracer needs admin.

Usage:
    python m2\\verify_oracle.py
"""
import ctypes
import os
import sys

# Oracle-only: a dummy key just lets the package import (agent.py constructs an
# anthropic client at import time). No API call is ever made by this harness.
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-lucent-oracle-only-unused")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
try:                                    # package may be `lucent` or `src`
    from lucent import ttd, config
    from lucent.oracle import verify_finding
    PKG = "lucent"
except ModuleNotFoundError:
    from src import ttd, config
    from src.oracle import verify_finding
    PKG = "src"


# --- What to test (edit to match your fixture) -------------------------------
SANDBOX     = config.SANDBOX_DIR
TARGET_EXE  = os.path.join(SANDBOX, "vuln.exe")
IMAGE_NAME  = "vuln.exe"
SINK_SYMBOL = "vuln!vuln"           # needs vuln.pdb (build.bat emits /Zi)

# Substring of the !analyze BUCKET_ID you expect for the known bug. LEAVE None on
# the first run: the harness prints the REAL bucket_id — copy the stable part
# back here, then rerun to exercise the identity check (matches_expected_bug).
EXPECTED_SIG = None

# The payload IS the command-line argument (argv[1]). buf is 16 bytes; 64 'A's
# blow well past the saved return address (no NUL so strcpy copies it all). 8
# 'A's fit and exit cleanly. Zero false positives on the clean case is the bar.
CRASH_ARG = "A" * 64                  # overflow -> return-address AV   (crash)
CLEAN_ARG = "A" * 8                   # fits in buf -> exit 0           (clean)
CASES = [("crash-64A", CRASH_ARG, True),
         ("clean-8A",  CLEAN_ARG, False)]


def preflight() -> bool:
    ok = True
    # gflags is NOT required for the stack fixture (no page heap); tttracer is
    # only needed if you want the reached_sink TTD milestone.
    for label, p in [("cdb", config.CDB), ("vuln.exe", TARGET_EXE)]:
        here = os.path.exists(p)
        print(f"[preflight] {label:11} {'OK     ' if here else 'MISSING'}  {p}")
        ok = ok and here
    for label, p in [("tttracer", config.TTTRACER)]:
        here = os.path.exists(p)
        print(f"[preflight] {label:11} {'OK     ' if here else 'MISSING'}  {p}"
              f"  (only needed for the TTD reached_sink milestone)")
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = None
    print(f"[preflight] admin: {admin}  (tttracer / TTD require it)")
    if admin is False:
        print("[preflight] NOTE: not elevated — the live AV verdict still works;"
              " only the TTD trace (reached_sink) will no-op.")
    return ok


def run_case(label: str, payload: str, expect_crash: bool, record_ttd: bool = True):
    args = {"target_cmd": [TARGET_EXE], "trigger_path": payload,
            "image_name": IMAGE_NAME, "page_heap": False}
    # Heartbeat BEFORE the slow call: verify_finding launches cdb (and, with TTD
    # on, tttracer + a replay), and the first !analyze -v downloads symbols from
    # Microsoft (minutes, one-time). flush=True so it shows even when stdout is
    # redirected to a file/pipe (Python block-buffers non-TTY output).
    print(f"\n[run] {label}: launching {'TTD record+replay' if record_ttd else 'cdb'}"
          f" (first !analyze may download symbols; up to {config.ORACLE_TIMEOUT}s each)...",
          flush=True)
    v = verify_finding(args, expected_sig=EXPECTED_SIG, record_ttd=record_ttd)

    print(f"\n=== {label}  (expect_crash={expect_crash}) ===")
    for k in ("crashed", "exception_code", "av_type", "fault_address",
              "rip_controlled", "bucket_id", "failure_bucket_id",
              "matches_expected_bug", "ttd_trace"):
        val = v.get(k)
        if k == "fault_address" and isinstance(val, int):
            val = hex(val)
        print(f"  {k:21} {val}")

    # 'reach' rung — did execution reach the vulnerable function? Read off the
    # TTD trace (primary source), not the agent's narration. None => no trace
    # (e.g. not elevated / TTD off), which is not the same as 0.
    trace = v.get("ttd_trace")
    reached = ttd.call_count(trace, SINK_SYMBOL)
    print(f"  reached_sink calls   {reached}   (symbol {SINK_SYMBOL!r})")
    return v, expect_crash


def confusion(results):
    print("\n=== confusion matrix (predicted 'crashed' vs known) ===")
    tp = fp = tn = fn = 0
    for v, expect in results:
        pred = bool(v.get("crashed"))
        if expect and pred:
            tp += 1
        elif expect and not pred:
            fn += 1
        elif not expect and pred:
            fp += 1
        else:
            tn += 1
    print(f"  TP (crash->crash) {tp}    TN (clean->clean) {tn}")
    print(f"  FALSE POSITIVES   {fp}    <-- must be 0 (an unfakeable oracle never cries crash on clean)")
    print(f"  FALSE NEGATIVES   {fn}    <-- must be 0")
    print("  RESULT:", "PASS" if (fp == 0 and fn == 0) else "FAIL")


def main():
    record_ttd = "--no-ttd" not in sys.argv
    print(f"[info] package `{PKG}` | sandbox {SANDBOX} | expected_sig {EXPECTED_SIG!r}"
          f" | ttd={'on' if record_ttd else 'off'}")
    if not record_ttd:
        print("[info] --no-ttd: cdb live-launch only (no tttracer windows, no admin;"
              " reached_sink will be None).")
    if not preflight():
        print("\n[abort] preflight failed - build the fixture first (m2\\build.bat).")
        return
    results = [run_case(*c, record_ttd=record_ttd) for c in CASES]
    confusion(results)


if __name__ == "__main__":
    main()
