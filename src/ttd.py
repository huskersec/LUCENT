"""
LUCENT — TTD trace replay helper (the missing seam under Phase-2 milestones).

The milestone detectors need to interrogate the recorded execution — "did we
reach function F?", "did a write land on object O?". The oracle records a Time
Travel Debugging trace but only hands back the OUTPUT DIRECTORY
(`verdict['ttd_trace']`); the trace itself is never opened. This module is what
opens it: locate the `.run` file and replay it under cdb to run a scripted
query against the TTD data model.

Why the trace and not the agent's narration: the recording is primary source.
"reached the sink / the corrupting write fired" read off the trace is
unfakeable in the same way the crash verdict is — that's what lets the
reach -> trigger -> control-proof ladder be a programmatic check, not a vibe.

⚠️ UNVERIFIED — same status as the rest of the skeleton. The cdb invocation for
opening a `.run` trace and the TTD data-model command strings
(`dx @$cursession.TTD.*`) below are written against documented TTD behavior but
have NOT been run end-to-end. Treat them as hypotheses to confirm against real
cdb output in the VM; primary output wins over anything asserted here. The
likely points of drift are (a) the exact `dx` accessor spelling/return shape and
(b) how the .run path surfaces in the oracle's output dir.
"""

import glob
import os
import re
import subprocess

from . import config


# dx echoes the expression then its value: `....Count : 3` (or `: 0x3`). Anchor
# on the .Count token so trace-open / symbol-load preamble can't match a stray
# `: <number>` line. Accept decimal or hex.
_COUNT_RE = re.compile(r"\.Count\s*:\s*(0x[0-9a-fA-F]+|\d+)")


def find_trace(ttd_dir: str | None) -> str | None:
    """Locate the `.run` trace file inside the oracle's TTD output directory.

    The oracle hands us the directory it pointed `tttracer -out` at; the trace
    lands inside as `*.run`. Returns the path, or None if there's nothing to
    replay (no dir, or recording was disabled / never produced a trace)."""
    if not ttd_dir or not os.path.isdir(ttd_dir):
        return None
    runs = sorted(glob.glob(os.path.join(ttd_dir, "*.run")))
    return runs[0] if runs else None


def replay_query(ttd_dir: str | None, commands: str,
                 timeout: int | None = None) -> str | None:
    """Open the recorded trace under cdb, run `commands`, return combined output.

    Returns None when there is no trace to replay (so callers can distinguish
    "no evidence" from "evidence says no"). cdb opens a TTD `.run` the same way
    it opens a dump — pass the path with `-z`; the session is replayable and
    exposes `@$cursession.TTD` across the whole recording."""
    trace = find_trace(ttd_dir)
    if trace is None:
        return None
    # Symbol path via the `-y` flag, NOT `.sympath` in the script: `.sympath X;
    # <cmd>` makes .sympath swallow the rest of the line (`;` separates path
    # ELEMENTS there, not commands), so the query never runs. Same trap as
    # oracle._run_cdb. Point it at the SANDBOX so vuln.pdb resolves (that's where
    # `reached_sink`'s "vuln!vuln" symbol lives); the server (SYMPATH) is not in
    # the path here, keeping the query offline and unable to stall on the network.
    script = f"{commands}; q"
    try:
        proc = subprocess.run(
            [config.CDB, "-y", config.SANDBOX_DIR, "-z", trace, "-c", script],
            capture_output=True, text=True,
            timeout=timeout or config.ORACLE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    return proc.stdout + proc.stderr


def _first_count(out: str | None) -> int | None:
    """Pull the integer a `dx ... .Count` line prints. None if unparsable."""
    if out is None:
        return None
    m = _COUNT_RE.search(out)
    return int(m.group(1), 0) if m else None


def call_count(ttd_dir: str | None, symbol: str) -> int | None:
    """How many times `symbol` (e.g. "clfs!ClfsEarlierLsn") was called across
    the trace, via the TTD Calls accessor. None == no trace / couldn't parse,
    which is NOT the same as 0 and callers should treat it as "unknown"."""
    out = replay_query(
        ttd_dir, f'dx -r1 @$cursession.TTD.Calls("{symbol}").Count')
    return _first_count(out)


def writes_to(ttd_dir: str | None, addr: int, length: int = 1) -> int | None:
    """Number of WRITES observed to [addr, addr+length) across the trace, via
    the TTD Memory accessor. This is the corrupting-write probe behind
    corrupted_object(). None == no trace / unparsable."""
    if not addr:
        return None
    start, end = hex(addr), hex(addr + max(1, length))
    out = replay_query(
        ttd_dir, f'dx -r1 @$cursession.TTD.Memory({start}, {end}, "w").Count')
    return _first_count(out)
