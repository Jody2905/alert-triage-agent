"""Agent loop tests with a scripted model and the real cyber-intel server (in-process)."""

import asyncio

from conftest import ALERTS_DIR, ScriptedModel, text, tool_use

from triage_agent.agent import triage
from triage_agent.bridge import ToolBridge
from triage_agent.report import render_markdown

ALERT = (ALERTS_DIR / "01_log4shell_web.txt").read_text()


def report(**overrides):
    base = {
        "title": "Log4Shell exploitation attempt against payments-api",
        "summary": "JNDI strings hit payments-api and the server then called out to the attacker's LDAP host.",
        "severity": "critical",
        "severity_reasoning": "KEV-listed CVSS 10 flaw, and the outbound LDAP connection suggests it worked.",
        "confidence": "high",
        "likely_true_positive": True,
        "vulnerabilities": [{"cve_id": "CVE-2021-44228", "relevance": "Exploit string in request headers",
                             "cvss_score": 10, "in_kev": True,
                             "source_ids": ["cve:CVE-2021-44228", "kev:CVE-2021-44228"]}],
        "attack_techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application",
                               "evidence": "JNDI lookup in User-Agent", "source_ids": ["attack:T1190"]}],
        "indicators": [{"value": "203.0.113.45", "type": "ip", "note": "LDAP callback host"}],
        "recommended_actions": ["Isolate 10.20.4.15", "Block 203.0.113.45", "Upgrade Log4j"],
        "open_questions": ["What was in the 48 KB download?"],
    }
    base.update(overrides)
    return base


LOOKUPS = [
    tool_use("t1", "extract_indicators", {"text": ALERT}),
]
RESEARCH = [
    text("Looking up the CVE and technique."),
    tool_use("t2", "lookup_cve", {"cve_id": "CVE-2021-44228"}),
    tool_use("t3", "get_attack_technique", {"technique_id": "T1190"}),
]


def run(turns, **kwargs):
    model = ScriptedModel(turns)

    async def go():
        async with ToolBridge.connect() as bridge:
            return await triage(ALERT, bridge, model, **kwargs), model
    return asyncio.run(go())


def test_happy_path():
    result, model = run([LOOKUPS, RESEARCH, [tool_use("t4", "submit_report", report())]])
    assert result.error is None
    assert result.verification["passed"], result.verification["issues"]
    assert result.run["turns"] == 3 and result.run["tool_calls"] == 3 and result.run["repair_rounds"] == 0
    assert result.run["input_tokens"] == 300
    # The model was offered the five MCP tools, the local extractor and submit_report.
    names = {t["name"] for t in model.requests[0]["tools"]}
    assert names == {"lookup_cve", "search_kev", "get_attack_technique", "search_corpus", "get_source",
                     "extract_indicators", "submit_report"}
    # Tool results went back to the model as tool_result blocks with real data.
    results = model.requests[2]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t2", "t3"]
    assert '"base_score": 10' in results[0]["content"]

    md = render_markdown(result.report, result.verification, result.run)
    assert "CVE-2021-44228" in md and "Citation check:** PASSED" in md


def test_repair_round_fixes_wrong_cvss():
    wrong = report(vulnerabilities=[{**report()["vulnerabilities"][0], "cvss_score": 9.8}])
    result, model = run([LOOKUPS, RESEARCH,
                         [tool_use("t4", "submit_report", wrong)],
                         [tool_use("t5", "submit_report", report())]])
    assert result.run["repair_rounds"] == 1
    assert result.verification["passed"]
    rejection = model.requests[3]["messages"][-1]["content"][0]
    assert rejection["is_error"] and "CVSS 9.8" in rejection["content"]


def test_unretrieved_citation_is_caught_when_repairs_run_out():
    # Cites T1059.001 without ever looking it up.
    invented = report(attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "evidence": "?",
                                          "source_ids": ["attack:T1059.001"]}])
    result, _ = run([LOOKUPS, RESEARCH, [tool_use("t4", "submit_report", invented)]], max_repairs=0)
    assert result.report is not None
    assert not result.verification["passed"]
    assert any(i["check"] == "citation_retrieved" for i in result.verification["issues"])
    assert "Citation check:** FAILED" in render_markdown(result.report, result.verification)


def test_tool_errors_go_back_to_the_model():
    result, model = run([[tool_use("t1", "lookup_cve", {"cve_id": "log4shell"})], RESEARCH,
                         [tool_use("t4", "submit_report", report())]])
    first = model.requests[1]["messages"][-1]["content"][0]
    assert first["is_error"] and "not a valid CVE id" in first["content"]
    assert result.run["tool_errors"] == 1 and result.verification["passed"]


def test_nudges_once_when_model_stops_without_report():
    result, model = run([LOOKUPS, RESEARCH, [text("Done, looks bad.")],
                         [tool_use("t4", "submit_report", report())]])
    assert "submit_report" in model.requests[3]["messages"][-1]["content"]
    assert result.verification["passed"]


def test_gives_up_after_max_turns():
    result, _ = run([LOOKUPS, RESEARCH], max_turns=2)
    assert result.report is None and "No report" in result.error
