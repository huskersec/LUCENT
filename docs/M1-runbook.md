# M1 — Agent-loop runbook

> **Status (2026-07-03).** **M1 is VM-verified.** `bench\run_agent_smoke.py` drove
> one full trajectory on `vuln.exe` — the model investigated the target, delivered
> a crashing `argv[1]`, called `submit_finding`, and the oracle returned
> `crashed=True`. **RESULT: PASS.** That is the M1 bar (the ReAct loop closes
> end-to-end, tool dispatch + oracle handshake work) and it is met. M1 is
> plumbing/contaminated — a walkable trajectory, **not** a capability claim.

M1 is the first rung: prove the loop *closes* before adding the patch-diff tooling
(M3) or a real target (M4). It exercises everything except discovery difficulty —
the model, the tool-use loop, the `run` tool, and the `submit_finding` → oracle
path — against a target whose answer is already known.

Fixture: the stack-overflow baseline — `bench/vuln.c` (16-byte buffer + unbounded
`strcpy`) built to `vuln.exe`. Payload is the command-line **argument**; a
long-enough arg overwrites the saved return address and the `ret` faults with an
access violation (`c0000005`).

---

## 1. What the loop is (`src/agent.py`)

A minimal, hand-rolled ReAct tool-use loop — no agent framework, on purpose
(building the primitive yourself is what teaches it). Each turn:

1. `client.messages.create(model, system, tools, messages)` — the whole growing
   history is resent (the API is stateless; prompt caching, added in M3a, keeps
   this cheap).
2. The **full** `resp.content` is appended back unchanged — including
   adaptive-thinking blocks, which `claude-sonnet-5` emits by default and which
   must be echoed verbatim for same-model continuation.
3. Every `tool_use` block is dispatched at `_dispatch` (the one swap point for the
   toolchain), and the results come back as a single `user` message of
   `tool_result`s keyed by `tool_use_id`.
4. The loop breaks when `stop_reason != "tool_use"` (the agent stopped on its own,
   or was truncated — see the M3a runbook's `max_tokens` note).

Tools available to the agent: **`run`** (one Windows `cmd.exe` line → combined
output + `[exit code: N]`), **`diff`** (ghidriff patch-diff; unused in M1),
**`submit_finding`** (→ `oracle.verify_finding`).

## 2. Prerequisites

- The M2 fixture built: `bench\build.bat` → `vuln.exe` in `C:\lucent\sandbox`
  (see the M2 runbook §1).
- A **real Anthropic credential** — `ANTHROPIC_API_KEY`, or an `ant auth login`
  profile. Unlike the oracle harnesses, this one actually calls the model.

## 3. Run

```powershell
python -u bench\run_agent_smoke.py
```

The driver builds the prompt, runs `run_agent(..., record_ttd=False, max_steps=16)`
(fast, symbol-free oracle path — no `tttracer`/admin), prints a summary, and writes
the walkable artifact to `C:\lucent\sandbox\agent_trajectory.txt`.

## 4. Expected result

```
=== agent run summary ===
  steps          <a handful>
  crashed         True
  exception_code  c0000005
  av_type         read_av
  RESULT: PASS (loop closed; oracle confirmed a crash)
```

The agent runs the target with a short arg (exit 0), escalates the length, sees a
large-negative exit code on a long arg, and submits it. The oracle re-confirms
independently. If it prints **INCOMPLETE — loop ran but no finding submitted**, the
agent stopped without a verdict (see the lesson below).

## 5. The lesson baked into the prompt

The first M1 attempt **stalled**: the agent was *blind to the crashes it caused*.
Two root causes, both fixed:

- **The `run` tool didn't surface the exit code.** A crashing target produces no
  stdout — the only observable signal is the return code. `_run_shell` now appends
  `\n[exit code: {returncode}]`, so `-1073741819` (`0xC0000005`) is visible.
- **Multi-line commands broke.** `cmd.exe /c` mangles multi-line input, so the
  prompt insists on **one line per `run`** and hands the agent a reliable recipe:
  `python -c "import subprocess; print('rc=', subprocess.run([exe, 'A'*N]).returncode)"`.

The prompt is deliberately **directive** here — it names the dynamic-testing
recipe and even a candidate length. That is fine for a *plumbing* smoke test (the
goal is "does the loop close," not "can the model discover the bug"). The
prompt-hygiene tightening (don't hand the agent the answer) and the compact payload
spec came later, in M3a — see that runbook.

## Guardrail note

The fixture is **known / self-authored (vendored from the Bug Museum)**, so every
run on it is **plumbing validation only**. It proves the loop drives the tools and
the oracle classifies a known crash correctly. It is **not** a capability claim
(contaminated; tag any `Task` built on it `contaminated=True`).
