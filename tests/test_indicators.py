from conftest import ALERTS_DIR

from triage_agent.indicators import decode_powershell, extract_indicators


def test_log4shell_alert():
    found = extract_indicators((ALERTS_DIR / "01_log4shell_web.txt").read_text())
    assert found["cve_ids"] == ["CVE-2021-44228"]
    kinds = {i["ip"]: i["kind"] for i in found["ips"]}
    assert kinds["10.20.4.15"] == "internal"
    assert kinds["203.0.113.45"] == "documentation"
    assert any(u.startswith("ldap://203.0.113.45:1389") for u in found["urls"])
    markers = {m["marker"] for m in found["suspicious_markers"]}
    assert "${jndi:" in markers and "${${" in markers


def test_encoded_powershell_is_decoded_and_mined():
    found = extract_indicators((ALERTS_DIR / "02_encoded_powershell.txt").read_text())
    assert len(found["decoded_powershell"]) == 1
    assert "DownloadString" in found["decoded_powershell"][0]["decoded"]
    # The URL only exists inside the encoded payload.
    assert "http://203.0.113.88:8080/stage2.ps1" in found["urls"]
    assert {m["marker"] for m in found["suspicious_markers"]} >= {"downloadstring", "-nop"}
    assert list(found["hashes"]) == ["sha256"]


def test_hash_lengths_do_not_overlap():
    sha256 = "a" * 64
    md5 = "b" * 32
    found = extract_indicators(f"file {sha256} and {md5}")
    assert found["hashes"] == {"sha256": [sha256], "md5": [md5]}


def test_decode_powershell_rejects_garbage():
    assert decode_powershell("not-base64!!") is None
    assert decode_powershell("QUJDREVGR0hJSktMTU5PUA==") is None  # ASCII, not UTF-16LE


def test_windows_event_ids_and_dedup():
    found = extract_indicators("EventID 4625 ... EventID 4625 ... EventID: 4624 CVE-2020-1472 cve-2020-1472")
    assert found["windows_event_ids"] == ["4625", "4624"]
    assert found["cve_ids"] == ["CVE-2020-1472"]
