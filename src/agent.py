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
        "name": "submit_finding",
        "description": "Report a confirmed vulnerability with the input that "
                       "triggers it. Call ONLY when you have a verified trigger.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "target_cmd": {"type": "array", "items": {"type": "string"}},
                # The PoC input, appended as the target's final argument. For an
                # arg-consuming target it is the literal payload (e.g. a long
                # string); for a file-reading target it is a path.
                "trigger_path": {"type": "string"},
                "image_name": {"type": "string"},
                # True only for HEAP-class bugs (enables Full Page Heap in the
                # oracle). Leave false/omit for the stack-overflow baseline.
                "page_heap": {"type": "boolean"},
            },
            "required": ["summary", "target_cmd", "trigger_path", "image_name"],
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


def _dispatch(name: str, inp: dict, expected_sig: str | None,
              record_ttd: bool = True) -> str:
    """Tool dispatch. THIS is the swap point for your toolchain."""
    if name == "run":
        return _run_shell(inp["cmd"])
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
        resp = client.messages.create(
            model=config.MODEL, max_tokens=config.MAX_TOKENS,
            system=SYSTEM, tools=TOOLS, messages=messages)
        run.steps += 1
        run.input_tokens += resp.usage.input_tokens
        run.output_tokens += resp.usage.output_tokens
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason != "tool_use":
            break  # agent stopped on its own

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
