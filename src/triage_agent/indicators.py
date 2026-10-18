"""Deterministic indicator extraction.

The model is good at judgement but bad at copying long hex strings and counting IPs.
So parsing is done in plain code and offered to the agent as a tool: it gets exact
indicators back and spends its effort on deciding what they mean.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\b(?:https?|ldap|ldaps|rmi|dns|ftp)://[^\s\"'<>}]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|me|online|site|vc|gov|edu)\b",
    re.IGNORECASE,
)
HASH_RES = {
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
}
# -e / -ec / -enc / -EncodedCommand followed by a base64 blob (PowerShell accepts these abbreviations).
PS_ENCODED_RE = re.compile(r"(?:^|\s)-(?:e|ec|en[a-z]*)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
WIN_EVENT_RE = re.compile(r"\b(?:EventID|Event ID|event_id)[\s:=]+(\d{3,5})\b", re.IGNORECASE)

# Strings worth pointing out to an analyst. These are hints, not verdicts: the agent
# still has to look techniques up and decide whether they apply.
SUSPICIOUS_MARKERS = {
    "${jndi:": "JNDI lookup string (typical of Log4Shell exploitation attempts)",
    "${${": "nested lookup obfuscation",
    "mimikatz": "credential dumping tool name",
    "sekurlsa": "credential dumping module name",
    "invoke-expression": "PowerShell Invoke-Expression",
    "iex(": "PowerShell IEX shorthand",
    "downloadstring": "PowerShell download cradle",
    "-windowstyle hidden": "hidden PowerShell window",
    "-w hidden": "hidden PowerShell window",
    "-nop": "PowerShell -NoProfile flag",
    " -enc ": "PowerShell encoded command",
    "/autodiscover/autodiscover.json": "Exchange Autodiscover path (abused by ProxyShell)",
    "/powershell?x-rps-cat": "Exchange remote PowerShell backend access",
    "new-mailboxexportrequest": "Exchange mailbox export (abused to write web shells)",
    "human2.aspx": "file name seen in MOVEit Transfer web shell activity",
    "certutil -urlcache": "certutil used to download files",
    "vssadmin delete shadows": "shadow copy deletion (common before ransomware encryption)",
}

PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def _unique(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


def _ip_kind(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if any(addr in net for net in PRIVATE_NETS):
        return "internal"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    if str(addr).startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return "documentation"  # RFC 5737 example ranges, common in sample logs
    return "external"


def decode_powershell(blob: str) -> str | None:
    """Decode a PowerShell -EncodedCommand argument (base64 of UTF-16LE). None if it isn't one."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    # Real commands are almost all printable ASCII; random bytes read as UTF-16 come out as CJK and symbols.
    plain = sum(" " <= ch <= "~" or ch in "\t\r\n" for ch in text)
    return text if text and plain / len(text) > 0.9 else None


def extract_indicators(text: str) -> dict[str, Any]:
    """Pull CVE ids, ATT&CK ids, IPs, URLs, domains, hashes, event ids and suspicious markers out of raw alert text."""
    lowered = text.lower()

    hashes: dict[str, list[str]] = {}
    claimed: set[str] = set()
    for kind, pattern in HASH_RES.items():  # longest first, so a sha256 isn't also reported as an md5
        found = [h.lower() for h in pattern.findall(text) if h.lower() not in claimed]
        found = [h for h in found if not any(h in longer for longer in claimed)]
        if found:
            hashes[kind] = _unique(found)
            claimed.update(found)

    urls = _unique(URL_RE.findall(text))
    ips = _unique(IPV4_RE.findall(text))
    domains = _unique(d.lower() for d in DOMAIN_RE.findall(text))

    decoded = []
    for blob in _unique(PS_ENCODED_RE.findall(text)):
        command = decode_powershell(blob)
        if command:
            decoded.append({"encoded": blob[:40] + ("..." if len(blob) > 40 else ""), "decoded": command})
            # Indicators hidden inside the decoded command count too.
            urls = _unique(urls + URL_RE.findall(command))
            ips = _unique(ips + IPV4_RE.findall(command))
            domains = _unique(domains + [d.lower() for d in DOMAIN_RE.findall(command)])
            lowered += "\n" + command.lower()

    return {
        "cve_ids": _unique(c.upper() for c in CVE_RE.findall(text)),
        "attack_technique_ids": _unique(TECHNIQUE_RE.findall(text)),
        "ips": [{"ip": ip, "kind": _ip_kind(ip)} for ip in ips],
        "urls": urls,
        "domains": domains,
        "hashes": hashes,
        "windows_event_ids": _unique(WIN_EVENT_RE.findall(text)),
        "decoded_powershell": decoded,
        "suspicious_markers": [
            {"marker": marker, "meaning": meaning} for marker, meaning in SUSPICIOUS_MARKERS.items() if marker in lowered
        ],
    }
