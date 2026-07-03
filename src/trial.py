"""
LUCENT — first end-to-end trial loop.

One clean trial = revert the target VM to a known-good golden snapshot, push a
binary + an input into the guest sandbox, run the binary under cdb to capture a
crash verdict, pull the artifacts back, parse the verdict, and revert again so
the box is left pristine for the next trial.

This module is the orchestration glue. It deliberately REUSES the project's
existing pieces rather than reinventing them:

  * `vsphere_target.VSphereTarget` — UUID-pinned VM control (revert/push/pull/run).
  * `oracle._parse_verdict`        — the cdb/!analyze verdict parser.
  * `oracle`'s cdb triage script   — reconstructed verbatim below so the output
                                     captured from the guest parses identically.
  * `config.SANDBOX_DIR / SYMPATH / CDB / TTTRACER` — paths and constants.

Why not just call `oracle.verify_finding()`? Because that function runs
cdb/gflags/tttracer through `subprocess` on the LOCAL machine — it is designed to
execute INSIDE the target VM. The trial driver runs on the orchestrator host, so
it instead executes cdb *in the guest* via VSphereTarget and feeds the captured
stdout into the same `_parse_verdict()` to get the identical structured verdict.

Secrets (vCenter + guest creds) come from the environment; nothing is hardcoded.

Dependencies: pyvmomi, requests (see vsphere_target.py).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
from pathlib import Path
from typing import Optional, Union

# Reuse config, the oracle's verdict parser, and the VM wrapper. Support being
# imported either as a package module (`from src import trial`) or run as a
# top-level script from inside src/.
try:
    from . import config
    from .oracle import _parse_verdict
    from .vsphere_target import VSphereTarget
except ImportError:  # pragma: no cover - script-mode fallback
    import config  # type: ignore
    from oracle import _parse_verdict  # type: ignore
    from vsphere_target import VSphereTarget  # type: ignore


_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = _REPO_ROOT / "bench" / "target.exe"
DEFAULT_IMAGE_NAME = "target.exe"
DEFAULT_SNAPSHOT = "golden"

_PathLike = Union[str, os.PathLike]


# --- guest path helpers -----------------------------------------------------
def _guest_join(*parts: str) -> str:
    r"""Join Windows guest path components with backslashes, regardless of the
    orchestrator's own OS (so this works when driving from Linux too)."""
    cleaned = [p.strip("\\/") for p in parts]
    return "\\".join(cleaned)


def _build_dbg_script() -> str:
    """The cdb triage script whose output `oracle._parse_verdict()` parses.

    Breaks on the first-chance access violation, runs to the fault, then dumps
    the exception record + faulting context / stack / !analyze bucket between
    `=== FAULT ===` and `=== END ===` markers that the parser keys on.

    The symbol path is NOT set here with `.sympath` — `.sympath X; <cmd>` makes
    .sympath swallow the rest of the line (`;` separates path elements there,
    not commands), so nothing after it runs. It is supplied via cdb's `-y` flag
    at the invocation instead (see run_trial). `.exr -1` gives the exception
    code/address without symbols; `kb`/`!analyze -v` need the symbol server.
    """
    return (
        "sxe av; "                       # break on first-chance AV
        "g; "                            # run forward to the fault
        ".echo === FAULT ===; "
        ".exr -1; "                      # exception record: code/addr/access, symbol-free
        ".ecxr; r; "                     # faulting register context
        "kb; "                           # stack with args
        "!analyze -v; "                  # bucket id + classification
        ".echo === END ===; q"
    )


# --- guest enumeration / artifact collection --------------------------------
def _guest_glob(target: VSphereTarget, pattern: str) -> list[str]:
    """Return guest file paths matching `pattern` (e.g. sandbox\\*.run) using a
    `dir /b /s` listing inside the guest. Returns [] when nothing matches."""
    cmd_exe = r"C:\Windows\System32\cmd.exe"
    _rc, out, _err = target.run(
        cmd_exe, args=f'/c dir /b /s "{pattern}"', capture=True, timeout=120
    )
    results = []
    for line in out.splitlines():
        line = line.strip()
        # dir /b /s prints absolute paths; skip noise like "File Not Found".
        if len(line) > 3 and line[1:3] == ":\\":
            results.append(line)
    return results


def _collect_artifacts(
    target: VSphereTarget, sandbox_dir: str, dest_dir: Path
) -> list[str]:
    """Pull any crash dumps / TTD traces / produced logs from the guest sandbox
    into `dest_dir`. Best-effort: missing files are not fatal."""
    pulled: list[str] = []
    for ext in ("*.run", "*.dmp", "*.log"):
        pattern = _guest_join(sandbox_dir, ext)
        for guest_path in _guest_glob(target, pattern):
            local_name = guest_path.rsplit("\\", 1)[-1]
            local_path = dest_dir / local_name
            try:
                target.pull(guest_path, str(local_path))
                pulled.append(str(local_path))
            except Exception:
                # A trace may be locked/open; skip rather than abort the trial.
                pass
    return pulled


# --- the trial ---------------------------------------------------------------
def run_trial(
    snapshot: str = DEFAULT_SNAPSHOT,
    target_local: _PathLike = DEFAULT_TARGET,
    input_local: Optional[_PathLike] = None,
    sandbox_dir: str = config.SANDBOX_DIR,
    image_name: str = DEFAULT_IMAGE_NAME,
    expected_sig: Optional[str] = None,
    record_ttd: bool = False,
    trials_root: _PathLike = "trials",
) -> dict:
    """Run a single clean LUCENT trial and return the verdict dict.

    Args:
        snapshot:     golden snapshot name to revert to before and after the run.
                      The golden image is assumed to already have Full Page Heap
                      enabled for `image_name` and the toolchain installed
                      (see setup-vm.ps1).
        target_local: local path to the target binary to push (default
                      bench/target.exe).
        input_local:  local path to the trigger input file. Required.
        sandbox_dir:  guest directory the binary + input land in and cdb runs
                      from (default config.SANDBOX_DIR = C:\\lucent\\sandbox).
        image_name:   the target's image name for page-heap (informational here;
                      page heap is baked into the golden snapshot).
        expected_sig: known !analyze BUCKET_ID substring for ground-truth
                      identity checking; None for discovery runs.
        record_ttd:   if True, record a TTD trace with tttracer first and triage
                      the replayed trace; otherwise do live cdb triage (the
                      simple clean path, matching oracle's record_ttd=False).
        trials_root:  local directory under which a per-run ./<timestamp>/ dir is
                      created to hold pulled artifacts + the cdb log.

    Returns:
        The structured verdict dict from oracle._parse_verdict (crashed,
        av_type, fault_address, bucket_id, matches_expected_bug, ...), augmented
        with 'artifacts' (local paths) and 'trial_dir'.
    """
    if input_local is None:
        raise ValueError("input_local is required (path to the trigger input).")

    target_local = Path(target_local)
    input_local = Path(input_local)
    if not target_local.is_file():
        raise FileNotFoundError(f"target binary not found: {target_local}")
    if not input_local.is_file():
        raise FileNotFoundError(f"input file not found: {input_local}")

    # Local per-trial artifact directory: ./trials/<timestamp>/
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    trial_dir = Path(trials_root) / stamp
    trial_dir.mkdir(parents=True, exist_ok=True)

    guest_target = _guest_join(sandbox_dir, target_local.name)
    guest_input = _guest_join(sandbox_dir, input_local.name)
    guest_script = _guest_join(sandbox_dir, "lucent_dbg.txt")

    dbg_script = _build_dbg_script()
    # Hand cdb the script via a command FILE (-cf) rather than -c, so the
    # semicolon/space-laden script survives the guest cmd.exe quoting intact.
    script_local = trial_dir / "lucent_dbg.txt"
    script_local.write_text(dbg_script, encoding="ascii")

    verdict: dict = {}
    cdb_out = ""
    with VSphereTarget() as target:
        try:
            # 2) clean slate
            target.revert(snapshot)

            # 3) stage binary + input + the debugger script
            target.push(str(target_local), guest_target)
            target.push(str(input_local), guest_input)
            target.push(str(script_local), guest_script)

            # 4) run the target under cdb and capture the triage output.
            if record_ttd:
                # Optional: record a TTD trace first (tttracer drives the target
                # directly), then triage by replaying the newest .run under cdb.
                ttd_out = _guest_join(sandbox_dir, "ttd")
                target.run(
                    config.TTTRACER,
                    args=f'-out "{ttd_out}" -dumpFull "{guest_target}" "{guest_input}"',
                    capture=True,
                    timeout=config.ORACLE_TIMEOUT,
                )
                runs = _guest_glob(target, _guest_join(sandbox_dir, "*.run"))
                if runs:
                    trace = runs[-1]
                    # Symbol path via -y (see _build_dbg_script). Guest capture
                    # goes to guest files (VSphereTarget.run), so there is no
                    # host-side pipe deadlock like oracle._run_cdb had.
                    _rc, cdb_out, _err = target.run(
                        config.CDB,
                        args=f'-y "{config.SYMPATH}" -cf "{guest_script}" -z "{trace}"',
                        capture=True,
                        timeout=config.ORACLE_TIMEOUT,
                    )
                else:
                    cdb_out = "=== NO TRACE ==="
            else:
                # Live triage: cdb launches the target directly (-g ignore
                # initial bp, -G ignore final bp), matching oracle.py. Symbol
                # path via -y, NOT .sympath (see _build_dbg_script).
                _rc, cdb_out, _err = target.run(
                    config.CDB,
                    args=f'-y "{config.SYMPATH}" -g -G -cf "{guest_script}" "{guest_target}" "{guest_input}"',
                    capture=True,
                    timeout=config.ORACLE_TIMEOUT,
                )

            # 5) pull artifacts (dumps / .run / logs) + persist the cdb log
            (trial_dir / "cdb_output.log").write_text(cdb_out, encoding="utf-8")
            artifacts = _collect_artifacts(target, sandbox_dir, trial_dir)
            artifacts.append(str(trial_dir / "cdb_output.log"))

            # 6) parse to a verdict using the oracle's own parser
            verdict = _parse_verdict(cdb_out, expected_sig, ttd_trace=None)
            verdict["artifacts"] = artifacts
            verdict["trial_dir"] = str(trial_dir)
        finally:
            # 7) always leave the target clean, even on failure
            try:
                target.revert(snapshot)
            except Exception as exc:  # pragma: no cover
                print(f"[trial] WARNING: post-trial revert failed: {exc}")

    return verdict


def _print_verdict(verdict: dict) -> None:
    """Print one concise human-readable result line."""
    fa = verdict.get("fault_address")
    fa_str = hex(fa) if isinstance(fa, int) else "n/a"
    matched = verdict.get("matches_expected_bug")
    matched_str = "n/a" if matched is None else ("yes" if matched else "NO")
    print(
        "[trial] verdict: "
        f"crashed={verdict.get('crashed')} "
        f"av_type={verdict.get('av_type')} "
        f"fault_address={fa_str} "
        f"bucket_id={verdict.get('bucket_id')} "
        f"matches_expected={matched_str} "
        f"-> artifacts in {verdict.get('trial_dir')}"
    )


# --- CLI / smoke entry point -------------------------------------------------
def _make_default_input(dest_dir: Path, size: int = 128) -> Path:
    """Generate a >64-byte trigger input (default 128 'A's) for target.exe."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"trigger_{size}.bin"
    path.write_bytes(b"A" * size)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run one LUCENT trial.")
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                        help="golden snapshot name (default: golden)")
    parser.add_argument("--target", default=str(DEFAULT_TARGET),
                        help="local path to target binary (default: bench/target.exe)")
    parser.add_argument("--input", default=None,
                        help="local path to trigger input "
                             "(default: generate a 128-byte input)")
    parser.add_argument("--sandbox", default=config.SANDBOX_DIR,
                        help=f"guest sandbox dir (default: {config.SANDBOX_DIR})")
    parser.add_argument("--expected-sig", default=None,
                        help="known !analyze BUCKET_ID substring, if any")
    parser.add_argument("--record-ttd", action="store_true",
                        help="record a TTD trace and triage the replay")
    args = parser.parse_args()

    # Default to a >64-byte input (the overflow case for bench/target.c).
    input_path = (
        Path(args.input) if args.input
        else _make_default_input(Path("trials") / "_inputs", size=128)
    )

    result = run_trial(
        snapshot=args.snapshot,
        target_local=args.target,
        input_local=input_path,
        sandbox_dir=args.sandbox,
        expected_sig=args.expected_sig,
        record_ttd=args.record_ttd,
    )
    _print_verdict(result)
