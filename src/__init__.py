"""LUCENT — agent-driven vulnerability-research / capability-eval system.

Theme: making opaque binaries legible (interpretability for compiled code).
"""

from .agent import run_agent, AgentRun, TOOLS
from .oracle import verify_finding, enable_page_heap, disable_page_heap
from .scoring import (
    Task, TrialResult, run_task, run_suite, score, suite_report, record,
    reached_sink, corrupted_object,
)

__all__ = [
    "run_agent", "AgentRun", "TOOLS",
    "verify_finding", "enable_page_heap", "disable_page_heap",
    "Task", "TrialResult", "run_task", "run_suite", "score",
    "suite_report", "record",
    "reached_sink", "corrupted_object",
]
