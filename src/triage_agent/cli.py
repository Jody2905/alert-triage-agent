"""Command line: triage-agent alerts/log4shell.txt  (or a folder of alerts, or - for stdin)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from .agent import DEFAULT_MODEL, triage
from .bridge import ToolBridge
from .report import render_markdown


def _collect(paths: list[str]) -> list[tuple[str, str]]:
    alerts = []
    for p in paths:
        if p == "-":
            alerts.append(("stdin", sys.stdin.read()))
            continue
        path = Path(p)
        files = sorted(f for f in path.iterdir() if f.suffix in {".txt", ".log", ".json"}) if path.is_dir() else [path]
        alerts += [(f.stem, f.read_text(encoding="utf-8")) for f in files]
    return alerts


async def _run(args: argparse.Namespace) -> int:
    from anthropic import AsyncAnthropic  # imported here so --help works without the SDK configured

    alerts = _collect(args.alerts)
    if not alerts:
        print("No alert files found.", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    client = AsyncAnthropic()
    rows = []

    for name, text in alerts:
        print(f"\n== {name} ==")
        # A fresh connection per alert keeps each run's citation ledger separate.
        async with ToolBridge.connect(args.server_cmd) as bridge:
            result = await triage(text, bridge, client, model=args.model, max_turns=args.max_turns,
                                  max_repairs=args.max_repairs, verbose=not args.quiet)
        (out / f"{name}.trace.json").write_text(json.dumps(result.to_trace(), indent=2, default=str), encoding="utf-8")
        if result.report is None:
            print(f"  FAILED: {result.error}")
            rows.append((name, "-", "no report", result.run))
            continue
        md = render_markdown(result.report, result.verification, result.run)
        (out / f"{name}.md").write_text(md, encoding="utf-8")
        status = "passed" if result.verification["passed"] else "FAILED"
        print(f"  -> {out / (name + '.md')}  severity={result.report.get('severity')}  verification={status}")
        rows.append((name, result.report.get("severity", "?"), status, result.run))

    print("\nalert                       severity       check    tools  tokens(in/out)  seconds")
    for name, sev, status, run in rows:
        print(f"{name[:27]:<27} {sev:<14} {status:<8} {run['tool_calls']:>5}  "
              f"{run['input_tokens']:>7}/{run['output_tokens']:<6}  {run['seconds']:>7}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="triage-agent", description="Triage security alerts with a Claude agent and cyber-intel-mcp.")
    parser.add_argument("alerts", nargs="+", help="alert files, folders of alerts, or - for stdin")
    parser.add_argument("--model", default=os.environ.get("TRIAGE_MODEL", DEFAULT_MODEL))
    parser.add_argument("--out", default="reports", help="where to write <alert>.md and <alert>.trace.json")
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--max-repairs", type=int, default=1, help="repair rounds after failed verification (0 disables)")
    parser.add_argument("--server-cmd", default=None,
                        help="launch the MCP server over stdio with this command instead of in-process, e.g. 'cyber-intel-mcp'")
    parser.add_argument("--quiet", action="store_true", help="don't print each tool call")
    args = parser.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        parser.error("set ANTHROPIC_API_KEY first (https://console.anthropic.com)")
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
