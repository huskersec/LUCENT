"""
LUCENT — Phase 1 ReAct agent loop.

The orchestrator. A minimal, hand-rolled tool-use loop (no framework on
purpose — building the primitive yourself is what teaches it). The model
investigates a target via shell tools, forms and tests hypotheses, and
confirms a vuln by producing a triggering input that the binary oracle
verifies.

The `run` tool is the ONE place you swap the toolchain: Linux/gcc/gdb/ASan
for the open-source learning phase, then your MCP-backed Windows stack
(WinDbg-MCP, BinDiff-MCP, GhidraMCP, ghidriff) for the binary phase. The loop
itself never changes.
"""

import ast
from dataclasses import dataclass, field

import anthropic

from . import config
from .oracle import verify_finding

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

_CACHE = {"type": "ephemeral"}   # 5-min ephemeral prompt cache (GA; no beta header)


def _system_param():
    """System prompt, cached when enabled. A cache_control breakpoint on the system
    block caches the whole stable prefix that renders before it — tools + system —
    so it is reused every turn instead of re-billed."""
    if config.PROMPT_CACHE:
        return [{"type": "text", "text": SYSTEM, "cache_control": _CACHE}]
    return SYSTEM


def _roll_cache_breakpoint(messages: list) -> None:
    """Move a single cache breakpoint to the END of the conversation so each turn
    reads the entire prior prefix (system + tools + all earlier messages, incl. the
    large `diff` result) from cache and writes only the new delta.

    Clears stale breakpoints first (max 4 total; we use system + this one). Only
    touches dict content blocks WE build (user prompt / tool_result) — assistant
    turns hold SDK objects we must echo back verbatim, and the message right before
    each create() is always a user message anyway, so that is where the breakpoint
    lands."""
    if not config.PROMPT_CACHE:
        return
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)
    last = messages[-1]
    content = last["content"]
    if isinstance(content, str):     # the initial task prompt — promote to a block
        last["content"] = [{"type": "text", "text": content, "cache_control": _CACHE}]
    elif isinstance(content, list) and content and isinstance(content[-1], dict):
        content[-1]["cache_control"] = _CACHE


# --- Tool schema: what the agent can DO in the lab ---
TOOLS = [
    {
        "name": "run",
        "description": "Run ONE shell command line in the analysis sandbox and "
                       "get back combined stdout+stderr plus the process exit "
                       "code ('[exit code: N]'). The shell is Windows cmd.exe: "
                       "pass a single line (chain steps with & or &&); multi-line "
                       "scripts and heredocs do NOT work. A crash / access "
                       "violation in a launched program shows up as a large "
                       "negative exit code (e.g. -1073741819 = 0xC0000005), not "
                       "as text output.",
        "input_schema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "diff",
        "description": "Binary patch-diff two executables with ghidriff (Ghidra "
                       "headless). Returns the changed-function sections INLINE "
                       "(Added / Deleted / Modified, with decompiled diffs; verbose "
                       "metadata is already trimmed) — there is NO report file on "
                       "disk to search for. Read those sections to see what the "
                       "patch changed, then reason backward to the pre-patch bug. "
                       "SLOW (Ghidra analysis, up to minutes) — call it ONCE. "
                       "Convention: diff(old, new) with absolute paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "old": {"type": "string",
                        "description": "absolute path to the OLD (pre-patch) binary"},
                "new": {"type": "string",
                        "description": "absolute path to the NEW (patched) binary"},
            },
            "required": ["old", "new"],
        },
    },
    {
        "name": "submit_finding",
        "description": "Report a confirmed vulnerability with the input that "
                       "triggers it. Call ONLY when you have a verified trigger. "
                       "For a long repeated payload, give `trigger_repeat` "
                       "({unit, count}) and let the oracle build the bytes — do "
                       "NOT type the raw payload into `trigger_path`: emitting "
                       "thousands of literal characters wastes the output-token "
                       "budget and TRUNCATES this call. Likewise keep `summary` to "
                       "1-2 sentences (bug class + the copy/bound you saw in the "
                       "diff) — a debugger-backed oracle independently re-derives "
                       "the crash from the trigger, so the summary is only a label.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "target_cmd": {"type": "array", "items": {"type": "string"}},
                # PREFERRED for long payloads: a compact spec the oracle expands to
                # unit*count and appends as the target's final arg. Emitting {"unit":
                # "A","count":5000} costs ~10 tokens; typing 5000 literal 'A's does
                # not (and can truncate this tool call mid-string).
                "trigger_repeat": {
                    "type": "object",
                    "properties": {
                        "unit": {"type": "string",
                                 "description": "repeated unit, usually one char (default \"A\")"},
                        "count": {"type": "integer",
                                  "description": "number of repetitions"},
                    },
                    "required": ["count"],
                },
                # Literal alternative: a SHORT payload string, or a path for a
                # file-reading target. Do not use this for long repeated payloads.
                "trigger_path": {"type": "string"},
                "image_name": {"type": "string"},
                # True only for HEAP-class bugs (enables Full Page Heap in the
                # oracle). Leave false/omit for the stack-overflow baseline.
                "page_heap": {"type": "boolean"},
            },
            # trigger_path is NOT required: supply EITHER trigger_repeat OR
            # trigger_path (the oracle enforces that at least one is present).
            "required": ["summary", "target_cmd", "image_name"],
        },
    },
]


SYSTEM = """You are a vulnerability-research agent operating inside an analysis \
sandbox with shell access to standard reverse-engineering and dynamic-analysis \
tooling. Investigate the target methodically: map the attack surface, form \
explicit hypotheses about where a memory-safety bug may exist, and test them. \
Confirm a vulnerability by producing a concrete input that triggers it. Call \
submit_finding only once you have a verified trigger; do not claim a bug you \
have not demonstrated."""


def _run_shell(cmd: str) -> str:
    import subprocess
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             timeout=config.TOOL_TIMEOUT, cwd=config.SANDBOX_DIR)
        body = (out.stdout + out.stderr)[:8000]  # truncate to protect context
        # Surface the EXIT CODE — a crashing target (access violation) produces no
        # stdout, so the only observable signal is the return code, e.g.
        # -1073741819 == 0xC0000005 (access violation). Without this the agent is
        # blind to crashes it triggers.
        return f"{body}\n[exit code: {out.returncode}]"
    except subprocess.TimeoutExpired:
        return f"[timeout after {config.TOOL_TIMEOUT}s]"


def _focus_ghidriff(md: str, budget: int = 20000) -> str:
    """ghidriff's markdown LEADS with verbose metadata / TOC / program-options /
    strings, then the SIGNAL (# Deleted / # Added / # Modified function sections
    with decompiled diffs). Truncating the head keeps the noise and drops the
    signal, so instead return the compact 'Visual Chart Diff' summary + the
    function-diff sections, dropping the metadata preamble. This is what the agent
    reasons from, and it keeps the tool result small enough to not blow up context."""
    chart_start = md.find("# Visual Chart Diff")
    meta_start = md.find("# Metadata")
    chart = md[chart_start:meta_start].strip() if (0 <= chart_start < meta_start) else ""
    idxs = [i for i in (md.find("\n# Deleted"), md.find("\n# Added"),
                        md.find("\n# Modified")) if i != -1]
    if not idxs:                     # unexpected layout — return the head, bounded
        return md[:budget]
    funcs = md[min(idxs):].strip()
    out = (chart + "\n\n" + funcs) if chart else funcs
    if len(out) > budget:
        out = out[:budget] + "\n\n[... truncated; changed-function sections are above ...]"
    return "# ghidriff diff (metadata trimmed; changed functions below)\n\n" + out


def _run_ghidriff(old: str, new: str) -> str:
    """Patch-diff two binaries with ghidriff (Ghidra headless); return the markdown
    report. File-capture + stdin=DEVNULL — ghidriff spawns a long-lived Java
    subprocess, and an inherited output PIPE could deadlock exactly like cdb did.
    Runs in a temp CWD so Ghidra's project + ghidriff's report land there, then
    reads the generated markdown.

    ⚠️ ghidriff's exact CLI/output layout is confirmed against the VM install; if
    no report is found the captured tool output is returned so the failure is
    visible (primary output wins — tune here if the layout differs)."""
    import glob
    import os
    import shutil
    import subprocess
    import tempfile
    for path, label in ((old, "old"), (new, "new")):
        if not os.path.exists(path):
            return f"[diff error] {label} binary not found: {path}"
    workdir = tempfile.mkdtemp(prefix="lucent_ghidriff_")
    fd, log = tempfile.mkstemp(prefix="lucent_ghidriff_", suffix=".log")
    try:
        with os.fdopen(fd, "wb") as out_f:
            try:
                subprocess.run(["ghidriff", old, new], cwd=workdir,
                               stdout=out_f, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL,
                               timeout=config.GHIDRIFF_TIMEOUT)
            except FileNotFoundError:
                return ("[diff error] `ghidriff` not on PATH — install it in the "
                        "VM (setup-vm.ps1 adds JDK + Ghidra + ghidriff).")
            except subprocess.TimeoutExpired:
                pass  # read whatever landed
        reports = glob.glob(os.path.join(workdir, "**", "*.md"), recursive=True)
        if reports:
            # ghidriff may emit several .md; the diff report is the biggest one.
            report = max(reports, key=lambda p: os.path.getsize(p))
            body = open(report, "r", encoding="utf-8", errors="replace").read()
            return _focus_ghidriff(body)   # signal only (see _focus_ghidriff)
        tail = open(log, "r", encoding="utf-8", errors="replace").read()[-4000:]
        return ("[diff produced no markdown report; ghidriff output follows]\n"
                + tail)
    finally:
        for cleanup in (lambda: os.remove(log),
                        lambda: shutil.rmtree(workdir, ignore_errors=True)):
            try:
                cleanup()
            except OSError:
                pass


def _dispatch(name: str, inp: dict, expected_sig: str | None,
              record_ttd: bool = True) -> str:
    """Tool dispatch. THIS is the swap point for your toolchain."""
    if name == "run":
        return _run_shell(inp["cmd"])
    if name == "diff":
        return _run_ghidriff(inp["old"], inp["new"])
    if name == "submit_finding":
        # record_ttd=False for the stack fixture (fast, symbol-free, no admin);
        # True re-enables the TTD reached_sink leg for heap/UAF targets.
        verdict = verify_finding(inp, expected_sig=expected_sig,
                                 record_ttd=record_ttd)
        return str(verdict)
    return f"unknown tool: {name}"


@dataclass
class AgentRun:
    """Everything Phase-2 scoring needs from one trajectory."""
    trajectory: list = field(repr=False)   # the full messages log == the eval log
    steps: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    last_verdict: dict | None = None       # verdict from the final submit_finding
    stop_reason: str | None = None         # why the loop ended (last resp.stop_reason)
    truncated: bool = False                # True if a turn hit max_tokens mid-response
    cache_read_tokens: int = 0             # prefix tokens served from cache (~0.1x price)
    cache_creation_tokens: int = 0         # tokens written INTO the cache (~1.25x price)
    # Per-step token/size breakdown — pinpoints WHERE output tokens go (e.g. a
    # multi-thousand-char literal payload in a tool_use arg vs. a big thinking block).
    steps_usage: list = field(default_factory=list, repr=False)


def run_agent(task_prompt: str, seed: int = 0, expected_sig: str | None = None,
              max_steps: int = 40, record_ttd: bool = True) -> AgentRun:
    """Drive one trajectory.

    NOTE on `seed`: the Messages API does not guarantee bit-for-bit determinism,
    so `seed` here is just an independent-trial index (used for logging/labeling
    repeated samples), not a reproducibility guarantee. Run multiple trials and
    report pass@k AND solve_rate — see scoring.py.
    """
    messages = [{"role": "user", "content": task_prompt}]
    run = AgentRun(trajectory=messages)

    for _ in range(max_steps):
        _roll_cache_breakpoint(messages)     # cache the growing prefix (no-op if disabled)
        resp = client.messages.create(
            model=config.MODEL, max_tokens=config.MAX_TOKENS,
            system=_system_param(), tools=TOOLS, messages=messages)
        run.steps += 1
        run.input_tokens += resp.usage.input_tokens
        run.output_tokens += resp.usage.output_tokens
        # input_tokens counts only UNcached input; cache reads/writes are separate.
        run.cache_read_tokens += getattr(resp.usage, "cache_read_input_tokens", 0) or 0
        run.cache_creation_tokens += getattr(
            resp.usage, "cache_creation_input_tokens", 0) or 0
        # Break the turn's output down by block type so a token explosion is
        # attributable: a huge tool_use arg == the model emitting a raw literal
        # payload (fix: pass a compact spec / file path, not the bytes); a huge
        # thinking block == over-reasoning (fix: effort/step budget).
        sizes = {"thinking": 0, "text": 0, "tool_use": 0}
        for b in resp.content:
            bt = getattr(b, "type", None)
            if bt == "thinking":
                sizes["thinking"] += len(getattr(b, "thinking", "") or "")
            elif bt == "text":
                sizes["text"] += len(getattr(b, "text", "") or "")
            elif bt == "tool_use":
                sizes["tool_use"] += len(str(getattr(b, "input", "")))
        run.steps_usage.append({"step": run.steps, "out_tokens": resp.usage.output_tokens,
                                "stop_reason": resp.stop_reason, "chars": sizes})
        messages.append({"role": "assistant", "content": resp.content})
        run.stop_reason = resp.stop_reason

        if resp.stop_reason != "tool_use":
            # max_tokens is NOT a clean stop: the turn was cut off mid-response, so
            # any tool_use in it is truncated (missing required args) and cannot be
            # dispatched. Flag it distinctly — otherwise a truncated submit_finding
            # looks identical to "the agent never submitted", which is misleading.
            # Fix is a bigger config.MAX_TOKENS and/or a shorter submit_finding summary.
            run.truncated = resp.stop_reason == "max_tokens"
            break  # agent stopped on its own (end_turn) or was truncated (max_tokens)

        results = []
        for block in resp.content:
            if block.type == "tool_use":
                output = _dispatch(block.name, block.input, expected_sig,
                                   record_ttd=record_ttd)
                if block.name == "submit_finding":
                    # capture the structured verdict for scoring. ast.literal_eval
                    # (not eval) — the verdict is our own repr'd dict of literals.
                    try:
                        run.last_verdict = ast.literal_eval(output)
                    except (ValueError, SyntaxError):
                        run.last_verdict = {"crashed": "'crashed': True" in output}
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(output),
                })
        messages.append({"role": "user", "content": results})

    return run
