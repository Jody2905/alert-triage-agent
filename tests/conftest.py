"""Shared test helpers.

Tests run against the cyber-intel sample snapshot through a real in-process MCP connection.
The model is replaced by ScriptedModel, which replays pre-written turns, so no API key or
network is needed and results are deterministic.
"""

import copy
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import cyber_intel_mcp

# Always use the bundled sample, even if a full snapshot was built locally.
os.environ["CYBER_INTEL_DATA_DIR"] = str(Path(cyber_intel_mcp.__file__).parent / "data" / "sample")

ALERTS_DIR = Path(__file__).resolve().parents[1] / "alerts"


def text(t: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=t)


def tool_use(id_: str, name: str, input_: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=input_)


class ScriptedModel:
    """Stands in for anthropic.AsyncAnthropic. Each call to messages.create returns the next scripted turn."""

    def __init__(self, turns: list[list[SimpleNamespace]]):
        self.turns = list(turns)
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    async def create(self, **kwargs: Any) -> SimpleNamespace:
        self.requests.append(copy.deepcopy(kwargs))  # the agent keeps appending to the same messages list
        if not self.turns:
            raise AssertionError("ScriptedModel ran out of turns")
        content = self.turns.pop(0)
        stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
        return SimpleNamespace(content=content, stop_reason=stop,
                               usage=SimpleNamespace(input_tokens=100, output_tokens=50))
