"""
LUCENT — central configuration.

Edit these paths to match your VM. Everything else in the project reads from
here, so this is the one file you touch when the lab layout changes.
"""

import os

# --- Model ---
# Sonnet tier for long multi-step trajectories (cost); switch to Opus-tier
# (LUCENT_MODEL=claude-opus-4-8) for the hard-reasoning experiments and compare.
# claude-sonnet-5 runs ADAPTIVE THINKING by default; agent.py echoes each
# response's full content (thinking blocks included) back unchanged, which is
# required for same-model continuation — don't strip it.
MODEL = os.environ.get("LUCENT_MODEL", "claude-sonnet-5")
# Per-turn output cap. Must fit adaptive-thinking tokens + a text preamble + the
# full tool_use block. 8192 was too tight: a verbose submit_finding `summary`
# blew the cap and TRUNCATED the tool call mid-JSON (stop_reason=max_tokens,
# missing required args), which the loop then misread as "agent never submitted".
# See agent.py's max_tokens handling and submit_finding's "keep summary short".
MAX_TOKENS = int(os.environ.get("LUCENT_MAX_TOKENS", "16384"))

# Prompt caching: the Messages API is stateless, so every turn resends system +
# tools + the whole growing message history — and in these trajectories the big
# repeated chunk is the `diff` tool result. Caching the stable prefix + rolling one
# breakpoint to the end of the conversation each turn lets later turns READ that
# prefix at ~0.1x instead of re-billing it. Set LUCENT_PROMPT_CACHE=0 to A/B the
# cost (cache reads/writes are reported per run). 5-min ephemeral cache (GA, no beta
# header); the slow `diff` runs once up front, so the fast later turns stay in-window.
PROMPT_CACHE = os.environ.get("LUCENT_PROMPT_CACHE", "1") != "0"

# --- Sandbox ---
# Working directory the agent's `run` tool executes inside. MUST be a disposable,
# snapshotted VM location. The agent runs arbitrary commands here.
SANDBOX_DIR = os.environ.get("LUCENT_SANDBOX", r"C:\lucent\sandbox")

# --- Debugging Tools for Windows ---
CDB = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
GFLAGS = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe"
TTTRACER = r"C:\Windows\System32\tttracer.exe"

# Microsoft public symbols + a local cache. Point the cache at fast storage.
# Override with LUCENT_SYMPATH to go fully local (no network) when the symbol
# server is unreachable, e.g.  LUCENT_SYMPATH="C:\Symbols;C:\lucent\sandbox"
# (vuln.pdb sits in the sandbox; cdb also auto-adds the exe's own directory).
SYMPATH = os.environ.get(
    "LUCENT_SYMPATH", r"SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols")

# --- Timeouts (seconds) ---
TOOL_TIMEOUT = 120        # per agent `run` tool call
# Per oracle verification (a single cdb run). The FIRST crash triage is much
# slower than later ones because !analyze -v force-downloads symbols from the
# Microsoft server; bump this (e.g. LUCENT_ORACLE_TIMEOUT=600) for a cold cache,
# then drop back once C:\Symbols is warm.
ORACLE_TIMEOUT = int(os.environ.get("LUCENT_ORACLE_TIMEOUT", "180"))
# Per ghidriff `diff` tool call. Ghidra headless analysis of TWO binaries from a
# cold project is slow (first run can be minutes); generous by default.
GHIDRIFF_TIMEOUT = int(os.environ.get("LUCENT_GHIDRIFF_TIMEOUT", "600"))

# --- Eval bookkeeping ---
RUNS_LOG = os.environ.get("LUCENT_RUNS_LOG", "runs.jsonl")
