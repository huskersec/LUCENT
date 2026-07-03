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

from dataclasses import dataclass, field

import anthropic

from . import config
from .oracle import verify_finding

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env


# --- Tool schema: what the agent can DO in the lab ---
TOOLS = [
    {
        "name": "run",
        "description": "Run a shell command in the analysis sandbox; returns "
                       "combined stdout+stderr (truncated).",
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
        return (out.stdout + out.stderr)[:8000]  # truncate to protect context
    except subprocess.TimeoutExpired:
        return f"[timeout after {config.TOOL_TIMEOUT}s]"


def _dispatch(name: str, inp: dict, expected_sig: str | None) -> str:
    """Tool dispatch. THIS is the swap point for your toolchain."""
    if name == "run":
        return _run_shell(inp["cmd"])
    if name == "submit_finding":
        verdict = verify_finding(inp, expected_sig=expected_sig)
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
              max_steps: int = 40) -> AgentRun:
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
                output = _dispatch(block.name, block.input, expected_sig)
                if block.name == "submit_finding":
                    # capture the structured verdict for scoring
                    try:
                        run.last_verdict = eval(output)  # verdict is a repr'd dict
                    except Exception:
                        run.last_verdict = {"crashed": "crashed" in output}
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(output),
                })
        messages.append({"role": "user", "content": results})

    return run
