"""The verifier is the part that has to be right: it is what catches a model making things up."""

import asyncio

from triage_agent.bridge import ToolBridge
from triage_agent.verify import verify_report

GOOD = {
    "severity": "critical",
    "vulnerabilities": [
        {"cve_id": "CVE-2021-44228", "relevance": "exploit string in logs", "cvss_score": 10, "in_kev": True,
         "source_ids": ["cve:CVE-2021-44228", "kev:CVE-2021-44228"]},
    ],
    "attack_techniques": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "evidence": "JNDI string",
         "source_ids": ["attack:T1190"]},
    ],
}
ALERT = "WAF hit, possible CVE-2021-44228"


def run(report, retrieved, alert=ALERT):
    async def go():
        async with ToolBridge.connect() as bridge:
            return await verify_report(report, bridge.fetch_source, retrieved, alert)
    return asyncio.run(go())


def checks(result):
    return {(i["level"], i["check"]) for i in result["issues"]}


ALL_RETRIEVED = {"cve:CVE-2021-44228", "kev:CVE-2021-44228", "attack:T1190"}


def test_good_report_passes():
    result = run(GOOD, ALL_RETRIEVED)
    assert result["passed"], result["issues"]
    assert result["citations_checked"] == 3


def test_citation_never_retrieved_fails():
    result = run(GOOD, {"cve:CVE-2021-44228"})
    assert not result["passed"]
    assert ("error", "citation_retrieved") in checks(result)


def test_invented_source_id_fails():
    bad = {**GOOD, "attack_techniques": [{**GOOD["attack_techniques"][0], "source_ids": ["attack:T9999"]}]}
    result = run(bad, ALL_RETRIEVED)
    assert ("error", "citation_exists") in checks(result)


def test_wrong_cvss_and_kev_status_fail():
    # CVE-2021-45105 is 5.9 and NOT in KEV; claim the opposite.
    bad = {**GOOD, "vulnerabilities": [{"cve_id": "CVE-2021-45105", "relevance": "x", "cvss_score": 7.5,
                                        "in_kev": True, "source_ids": ["cve:CVE-2021-45105"]}]}
    result = run(bad, ALL_RETRIEVED | {"cve:CVE-2021-45105"}, alert="")
    assert {("error", "cvss_matches"), ("error", "kev_matches")} <= checks(result)


def test_missing_citation_fails():
    bad = {**GOOD, "vulnerabilities": [{**GOOD["vulnerabilities"][0], "source_ids": []}]}
    assert ("error", "missing_citation") in checks(run(bad, ALL_RETRIEVED))


def test_warnings_do_not_fail():
    report = {**GOOD, "attack_techniques": [{**GOOD["attack_techniques"][0], "name": "Exploit Web App"}]}
    result = run(report, ALL_RETRIEVED, alert=ALERT + " and CVE-2021-45105")
    assert result["passed"]
    assert {("warning", "technique_name"), ("warning", "coverage")} <= checks(result)


def test_bad_severity_fails():
    assert ("error", "schema") in checks(run({**GOOD, "severity": "urgent"}, ALL_RETRIEVED))
