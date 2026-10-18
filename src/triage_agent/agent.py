"""The agent loop: Claude decides which tools to call, the bridge runs them, and the
verifier checks the final report. If verification fails, the problems go back to the model
for a repair round (agent + verification), up to `max_repairs` times.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .bridge import ToolBridge
from .prompts import FINAL_NUDGE, SYSTEM_PROMPT, repair_message
from .report import REPORT_SCHEMA
from .verify import verify_report

DEFAULT_MODEL = "claude-sonnet-5-5"

SUBMIT_TOOL = {
    "name": "submit_report",
    "description": "Submit the finished incident report. Call this once, at the end.",
    "input_schema": REPORT_SCHEMA,
}


@dataclass
class TriageResult:
    report: dict[str, Any] | None
    verification: dict[str, Any] | None
    run: dict[str, Any]
    steps: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_trace(self) -> dict[str, Any]:
        return asdict(self)


async def triage(alert_text: str, bridge: ToolBridge, model_client: Any, *, model: str = DEFAULT_MODEL,
                 max_turns: int = 15, max_repairs: int = 1, max_tokens: int = 4096,
                 verbose: bool = False) -> TriageResult:
    """Triage one alert. `model_client` is an anthropic.AsyncAnthropic (or anything with the same
    `messages.create` shape, which is how the tests run without an API key)."""
    started = time.perf_counter()
    tools = bridge.claude_tools([SUBMIT_TOOL])
    messages: list[dict[str, Any]] = [{
        "role": "user",
        "content": f"<alert>\n{alert_text.strip()}\n</alert>\n\nTriage this alert.",
    }]
    usage = {"input_tokens": 0, "output_tokens": 0}
    steps: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    repairs = 0
    nudged = False
    turn = 0
    finished = False

    def log(msg: str) -> None:
        if verbose:
            print(msg, flush=True)

    while turn < max_turns and not finished:
        turn += 1
        response = await model_client.messages.create(
            model=model, max_tokens=max_tokens, system=SYSTEM_PROMPT, tools=tools, messages=messages,
        )
        usage["input_tokens"] += getattr(response.usage, "input_tokens", 0) or 0
        usage["output_tokens"] += getattr(response.usage, "output_tokens", 0) or 0
        messages.append({"role": "assistant", "content": [_block_to_dict(b) for b in response.content]})

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            if nudged:
                break
            nudged = True
            messages.append({"role": "user", "content": FINAL_NUDGE})
            continue

        results: list[dict[str, Any]] = []
        # Run lookups before any submit_report in the same turn, so the ledger is current when we verify.
        for block in sorted(tool_uses, key=lambda b: b.name == "submit_report"):
            if block.name != "submit_report":
                text, is_error = await bridge.call(block.name, dict(block.input))
                steps.append({"turn": turn, "tool": block.name, "input": dict(block.input),
                              "is_error": is_error, "result_preview": text[:300]})
                log(f"  [{turn}] {block.name}({_short(block.input)}){' -> ERROR' if is_error else ''}")
                results.append(_tool_result(block.id, text, is_error))
                continue

            candidate = dict(block.input)
            verification = await verify_report(candidate, bridge.fetch_source, bridge.ledger, alert_text)
            report = candidate
            steps.append({"turn": turn, "tool": "submit_report", "verification": verification["summary"],
                          "passed": verification["passed"]})
            log(f"  [{turn}] submit_report -> {verification['summary']}")
            if verification["passed"] or repairs >= max_repairs:
                results.append(_tool_result(block.id, "Report accepted.", False))
                finished = True
            else:
                repairs += 1
                results.append(_tool_result(block.id, repair_message(verification["issues"]), True))
        messages.append({"role": "user", "content": results})

    run = {
        "model": model,
        "turns": turn,
        "tool_calls": len(bridge.calls),
        "tool_errors": sum(c.is_error for c in bridge.calls),
        "repair_rounds": repairs,
        "seconds": round(time.perf_counter() - started, 2),
        **usage,
    }
    error = None if report is not None else f"No report submitted within {max_turns} turns."
    return TriageResult(report=report, verification=verification, run=run, steps=steps, error=error)


def _tool_result(tool_use_id: str, text: str, is_error: bool) -> dict[str, Any]:
    block: dict[str, Any] = {"type": "tool_result", "tool_use_id": tool_use_id, "content": text}
    if is_error:
        block["is_error"] = True
    return block


def _block_to_dict(block: Any) -> dict[str, Any]:
    if block.type == "text":
        return {"type": "text", "text": block.text}
    if block.type == "tool_use":
        return {"type": "tool_use", "id": block.id, "name": block.name, "input": dict(block.input)}
    return block.model_dump(exclude_none=True)  # e.g. thinking blocks, which must be passed back unchanged


def _short(args: Any, limit: int = 70) -> str:
    text = ", ".join(f"{k}={v!r}" for k, v in dict(args).items())
    return text if len(text) <= limit else text[:limit] + "..."
