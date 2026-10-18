"""Checks a finished report against the data, without trusting the model.

Errors fail the report (and trigger a repair round if any are left):
  - an item cites nothing, or cites a source id that doesn't exist
  - a cited source id was never returned by a tool in this run (the model invented it)
  - a CVSS score or KEV status disagrees with the record
Warnings are shown to the analyst but don't fail the report:
  - a citation that exists but is about a different CVE/technique than the item
  - a technique name that doesn't match ATT&CK
  - a CVE named in the alert that the report never addresses
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from .indicators import CVE_RE
from .report import SEVERITIES, cited_source_ids

FetchSource = Callable[[str], Awaitable[dict[str, Any] | None]]


async def verify_report(report: dict[str, Any], fetch_source: FetchSource, retrieved: set[str],
                        alert_text: str = "") -> dict[str, Any]:
    issues: list[dict[str, str]] = []

    def add(level: str, check: str, message: str) -> None:
        issues.append({"level": level, "check": check, "message": message})

    if report.get("severity") not in SEVERITIES:
        add("error", "schema", f"severity must be one of {SEVERITIES}, got {report.get('severity')!r}")

    records: dict[str, dict[str, Any] | None] = {}

    async def record(source_id: str) -> dict[str, Any] | None:
        if source_id not in records:
            records[source_id] = await fetch_source(source_id)
        return records[source_id]

    # 1. Every citation exists and was actually retrieved during this run.
    for sid in cited_source_ids(report):
        if await record(sid) is None:
            add("error", "citation_exists", f"`{sid}` does not exist in the data snapshot")
        elif sid not in retrieved:
            add("error", "citation_retrieved", f"`{sid}` was cited but no tool returned it during this run")

    # 2. Vulnerabilities: cited, and the numbers match the record.
    for v in report.get("vulnerabilities") or []:
        cve = str(v.get("cve_id", "")).upper()
        sids = v.get("source_ids") or []
        if not sids:
            add("error", "missing_citation", f"{cve} has no source_ids")
        elif not any(s.endswith(":" + cve) for s in sids):
            add("warning", "citation_relevance", f"{cve} cites {sids}, none of which is a record for {cve}")

        cve_record = await record(f"cve:{cve}")
        if cve_record is not None and v.get("cvss_score") is not None:
            actual = (cve_record.get("cvss") or {}).get("base_score")
            if actual is not None and abs(float(v["cvss_score"]) - float(actual)) > 0.05:
                add("error", "cvss_matches", f"{cve} reported CVSS {v['cvss_score']} but the record says {actual}")

        actually_in_kev = await record(f"kev:{cve}") is not None
        if bool(v.get("in_kev")) != actually_in_kev:
            add("error", "kev_matches",
                f"{cve} reported in_kev={bool(v.get('in_kev'))} but it is {'in' if actually_in_kev else 'not in'} the KEV catalog")

    # 3. Techniques: cited, real, and named correctly.
    for t in report.get("attack_techniques") or []:
        tid = str(t.get("technique_id", "")).upper()
        sids = t.get("source_ids") or []
        if not sids:
            add("error", "missing_citation", f"{tid} has no source_ids")
        elif f"attack:{tid}" not in sids:
            add("warning", "citation_relevance", f"{tid} cites {sids} but not `attack:{tid}`")
        technique = await record(f"attack:{tid}")
        if technique is None:
            add("error", "technique_exists", f"{tid} is not an ATT&CK Enterprise technique in the snapshot")
        elif t.get("name") and t["name"].strip().lower() != str(technique.get("name", "")).lower():
            add("warning", "technique_name", f"{tid} is named '{t['name']}' but ATT&CK calls it '{technique.get('name')}'")

    # 4. Coverage: CVEs named in the alert should be addressed.
    reported = {str(v.get("cve_id", "")).upper() for v in report.get("vulnerabilities") or []}
    reported_text = str(report).upper()
    for cve in {c.upper() for c in CVE_RE.findall(alert_text)}:
        if cve not in reported and cve not in reported_text:
            add("warning", "coverage", f"{cve} appears in the alert but the report never mentions it")

    errors = sum(i["level"] == "error" for i in issues)
    warnings = len(issues) - errors
    n_cited = len(cited_source_ids(report))
    return {
        "passed": errors == 0,
        "errors": errors,
        "warnings": warnings,
        "citations_checked": n_cited,
        "summary": f"{n_cited} citations checked, {errors} errors, {warnings} warnings",
        "issues": issues,
    }
