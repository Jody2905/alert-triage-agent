"""The incident report: the schema the agent must fill in, and how it is rendered.

The agent finishes by calling `submit_report` with JSON matching REPORT_SCHEMA. Forcing a
structured report (instead of free text) is what makes the verifier possible: every claim
arrives with the source ids it rests on.
"""

from __future__ import annotations

from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "informational"]

_SOURCE_IDS = {
    "type": "array",
    "items": {"type": "string"},
    "description": "source_id values returned by cyber-intel tools that support this item, e.g. 'cve:CVE-2021-44228'",
}

REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "One-line incident title"},
        "summary": {"type": "string", "description": "2-4 sentences: what happened, how sure you are, what matters most"},
        "severity": {"type": "string", "enum": SEVERITIES},
        "severity_reasoning": {"type": "string", "description": "Why this severity, in one or two sentences"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "likely_true_positive": {"type": "boolean"},
        "vulnerabilities": {
            "type": "array",
            "description": "CVEs relevant to this alert. Copy cvss_score and in_kev from tool results, never from memory.",
            "items": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "relevance": {"type": "string", "description": "Why this CVE matters for this alert"},
                    "cvss_score": {"type": ["number", "null"]},
                    "in_kev": {"type": "boolean"},
                    "source_ids": _SOURCE_IDS,
                },
                "required": ["cve_id", "relevance", "cvss_score", "in_kev", "source_ids"],
            },
        },
        "attack_techniques": {
            "type": "array",
            "description": "MITRE ATT&CK techniques the activity matches",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "name": {"type": "string"},
                    "evidence": {"type": "string", "description": "Which part of the alert shows this technique"},
                    "source_ids": _SOURCE_IDS,
                },
                "required": ["technique_id", "name", "evidence", "source_ids"],
            },
        },
        "indicators": {
            "type": "array",
            "description": "IOCs worth blocking or hunting for",
            "items": {
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "type": {"type": "string", "description": "ip, domain, url, hash, file, account, ..."},
                    "note": {"type": "string"},
                },
                "required": ["value", "type"],
            },
        },
        "recommended_actions": {
            "type": "array",
            "description": "Concrete next steps in priority order (contain, investigate, remediate)",
            "items": {"type": "string"},
        },
        "open_questions": {
            "type": "array",
            "description": "What the alert alone cannot answer and an analyst should check",
            "items": {"type": "string"},
        },
    },
    "required": [
        "title", "summary", "severity", "severity_reasoning", "confidence", "likely_true_positive",
        "vulnerabilities", "attack_techniques", "indicators", "recommended_actions", "open_questions",
    ],
}


def cited_source_ids(report: dict[str, Any]) -> list[str]:
    """Every source id the report cites, in order of first appearance."""
    seen: dict[str, None] = {}
    for section in ("vulnerabilities", "attack_techniques"):
        for item in report.get(section) or []:
            for sid in item.get("source_ids") or []:
                seen.setdefault(sid, None)
    return list(seen)


def render_markdown(report: dict[str, Any], verification: dict[str, Any] | None = None,
                    run: dict[str, Any] | None = None) -> str:
    lines = [f"# {report.get('title', 'Incident report')}", ""]
    sev = str(report.get("severity", "?")).upper()
    tp = "likely true positive" if report.get("likely_true_positive") else "possibly benign / false positive"
    lines += [f"**Severity:** {sev} · **Confidence:** {report.get('confidence', '?')} · {tp}", ""]
    if verification is not None:
        badge = "PASSED" if verification["passed"] else "FAILED"
        lines += [f"**Citation check:** {badge} ({verification['summary']})", ""]
    lines += ["## Summary", "", report.get("summary", ""), "", f"_Severity reasoning:_ {report.get('severity_reasoning', '')}", ""]

    vulns = report.get("vulnerabilities") or []
    if vulns:
        lines += ["## Vulnerabilities", "", "| CVE | CVSS | CISA KEV | Why it matters | Sources |", "|---|---|---|---|---|"]
        for v in vulns:
            score = "n/a" if v.get("cvss_score") is None else v["cvss_score"]
            kev = "Yes" if v.get("in_kev") else "No"
            lines.append(f"| {v['cve_id']} | {score} | {kev} | {_cell(v.get('relevance', ''))} | {_sources(v)} |")
        lines.append("")

    techniques = report.get("attack_techniques") or []
    if techniques:
        lines += ["## MITRE ATT&CK techniques", "", "| Technique | Evidence in the alert | Sources |", "|---|---|---|"]
        for t in techniques:
            lines.append(f"| {t['technique_id']} {t.get('name', '')} | {_cell(t.get('evidence', ''))} | {_sources(t)} |")
        lines.append("")

    iocs = report.get("indicators") or []
    if iocs:
        lines += ["## Indicators", ""]
        lines += [f"- `{i['value']}` ({i.get('type', '?')})" + (f": {i['note']}" if i.get("note") else "") for i in iocs]
        lines.append("")

    for heading, key, numbered in (("Recommended actions", "recommended_actions", True), ("Open questions", "open_questions", False)):
        items = report.get(key) or []
        if items:
            lines += [f"## {heading}", ""]
            lines += [f"{n}. {a}" if numbered else f"- {a}" for n, a in enumerate(items, 1)]
            lines.append("")

    if verification is not None and verification["issues"]:
        lines += ["## Verification issues", ""]
        lines += [f"- **{i['level']}** ({i['check']}): {i['message']}" for i in verification["issues"]]
        lines.append("")

    if run:
        lines += [
            "---",
            f"_Model {run['model']} · {run['turns']} turns · {run['tool_calls']} tool calls · "
            f"{run['input_tokens']:,} in / {run['output_tokens']:,} out tokens · {run['seconds']:.1f}s · "
            f"repair rounds {run['repair_rounds']}_",
            "",
        ]
    return "\n".join(lines)


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _sources(item: dict[str, Any]) -> str:
    return ", ".join(f"`{s}`" for s in item.get("source_ids") or []) or "none"
