"""Connects the agent to the cyber-intel MCP server and to local tools.

The bridge does three jobs:
1. turns MCP tool definitions into Claude API tool definitions,
2. runs tool calls and turns results into text the model can read,
3. keeps a ledger of every source_id a tool actually returned, so the verifier can
   tell a real citation from one the model made up.
"""

from __future__ import annotations

import json
import shlex
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import Client, StdioServerParameters

from .indicators import extract_indicators

MAX_RESULT_CHARS = 8000

LOCAL_TOOLS: list[dict[str, Any]] = [
    {
        "name": "extract_indicators",
        "description": (
            "Parse raw alert or log text and return exact indicators: CVE ids, ATT&CK ids, IPs (tagged "
            "internal/external), URLs, domains, file hashes, Windows event ids, decoded PowerShell "
            "-EncodedCommand payloads, and suspicious markers. Call this first on the alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Raw alert or log text"}},
            "required": ["text"],
        },
    },
]


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    is_error: bool
    result_preview: str


@dataclass
class ToolBridge:
    """Use as `async with ToolBridge.connect(...) as bridge:`."""

    client: Client
    mcp_tools: list[dict[str, Any]] = field(default_factory=list)
    ledger: set[str] = field(default_factory=set)
    calls: list[ToolCall] = field(default_factory=list)

    # ---- connection -------------------------------------------------------------------

    @classmethod
    def connect(cls, server_command: str | None = None) -> "_BridgeContext":
        """In-process cyber-intel server by default; or launch `server_command` over stdio."""
        if server_command:
            parts = shlex.split(server_command)
            target: Any = StdioServerParameters(command=parts[0], args=parts[1:])
        else:
            from cyber_intel_mcp.server import mcp as in_process_server

            target = in_process_server
        return _BridgeContext(target)

    # ---- tool definitions -------------------------------------------------------------

    def claude_tools(self, extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        return self.mcp_tools + LOCAL_TOOLS + (extra or [])

    # ---- calling tools ----------------------------------------------------------------

    async def call(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run a tool. Returns (text for the model, is_error). Never raises for tool failures."""
        if name == "extract_indicators":
            text, is_error = _to_text(extract_indicators(str(arguments.get("text", "")))), False
        elif name in {t["name"] for t in self.mcp_tools}:
            try:
                result = await self.client.call_tool(name, arguments)
            except Exception as exc:  # transport problems, bad arguments rejected client-side
                text, is_error = f"Tool call failed: {exc}", True
            else:
                is_error = bool(result.is_error)
                if result.structured_content is not None:
                    if not is_error:
                        self.ledger.update(collect_source_ids(result.structured_content))
                    text = _to_text(result.structured_content)
                else:
                    text = "\n".join(getattr(c, "text", "") for c in result.content)
        else:
            text, is_error = f"Unknown tool '{name}'.", True

        self.calls.append(ToolCall(name, arguments, is_error, text[:200]))
        return text, is_error

    async def fetch_source(self, source_id: str) -> dict[str, Any] | None:
        """Look up a source id for verification. Does not touch the ledger or the call log."""
        result = await self.client.call_tool("get_source", {"source_id": source_id})
        data = result.structured_content or {}
        return data.get("record") if data.get("found") else None


class _BridgeContext:
    def __init__(self, target: Any):
        self._target = target
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> ToolBridge:
        client = await self._stack.enter_async_context(Client(self._target))
        tools = (await client.list_tools()).tools
        bridge = ToolBridge(client=client)
        bridge.mcp_tools = [
            {"name": t.name, "description": t.description or "", "input_schema": t.input_schema} for t in tools
        ]
        return bridge

    async def __aexit__(self, *exc: Any) -> None:
        await self._stack.aclose()


def collect_source_ids(data: Any) -> set[str]:
    """Find every value under a `source_id` / `source_ids` key, at any depth."""
    found: set[str] = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "source_id" and isinstance(value, str):
                found.add(value)
            elif key == "source_ids" and isinstance(value, list):
                found.update(v for v in value if isinstance(v, str))
            else:
                found |= collect_source_ids(value)
    elif isinstance(data, list):
        for item in data:
            found |= collect_source_ids(item)
    return found


def _to_text(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + f'... [truncated, {len(text) - MAX_RESULT_CHARS} more characters]'
    return text
