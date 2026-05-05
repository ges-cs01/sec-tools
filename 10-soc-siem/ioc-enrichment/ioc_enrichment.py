#!/usr/bin/env python3
"""
IOC Enrichment Tool
Queries VirusTotal and AbuseIPDB for IPs and file hashes,
and generates a structured Markdown report.

Usage:
    python ioc_enrichment.py -i iocs/sample.txt -o reports/
    python ioc_enrichment.py --ioc 1.2.3.4
    python ioc_enrichment.py --ioc d41d8cd98f00b204e9800998ecf8427e
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

VT_BASE   = "https://www.virustotal.com/api/v3"
ABIP_BASE = "https://api.abuseipdb.com/api/v2"

MITRE_MAP = {
    "ip":   "T1071 - Application Layer Protocol / T1041 - Exfiltration Over C2",
    "hash": "T1204 - User Execution / T1059 - Command and Scripting Interpreter",
}

VERDICT = {
    "malicious":  "MALICIOUS",
    "suspicious": "SUSPICIOUS",
    "clean":      "CLEAN",
    "unknown":    "UNKNOWN",
}

@dataclass
class IOCResult:
    ioc:          str
    ioc_type:     str                      # "ip" | "hash"
    verdict:      str = "unknown"
    vt_data:      dict = field(default_factory=dict)
    abip_data:    dict = field(default_factory=dict)
    error:        Optional[str] = None

def detect_type(ioc: str) -> Optional[str]:
    ioc = ioc.strip()
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):   # MD5
        return "hash"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):   # SHA256
        return "hash"
    return None

def load_iocs_from_file(path: str) -> list[str]:
    iocs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(line)
    return iocs

def verdict_from_vt(stats: dict) -> str:
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= 3:
        return "malicious"
    if malicious >= 1 or suspicious >= 3:
        return "suspicious"
    return "clean"

def rate_limit(seconds: float = 1.0):
    """Respect free-tier rate limits (4 req/min VT, 1 req/s AbuseIPDB)."""
    time.sleep(seconds)

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    def lookup_ip(self, ip: str) -> dict:
        url = f"{VT_BASE}/ip_addresses/{ip}"
        r = requests.get(url, headers=self.headers, timeout=15)
        r.raise_for_status()
        return r.json()

    def lookup_hash(self, hash_val: str) -> dict:
        url = f"{VT_BASE}/files/{hash_val}"
        r = requests.get(url, headers=self.headers, timeout=15)
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        return r.json()

class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def lookup_ip(self, ip: str) -> dict:
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        r = requests.get(
            f"{ABIP_BASE}/check",
            headers=self.headers,
            params=params,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

def enrich_ip(ip: str, vt: VirusTotalClient, abip: AbuseIPDBClient) -> IOCResult:
    result = IOCResult(ioc=ip, ioc_type="ip")
    try:
        vt_resp = vt.lookup_ip(ip)
        rate_limit()
        abip_resp = abip.lookup_ip(ip)
        rate_limit()

        attrs = vt_resp.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.vt_data = {
            "stats":        stats,
            "country":      attrs.get("country", "N/A"),
            "asn":          attrs.get("asn", "N/A"),
            "as_owner":     attrs.get("as_owner", "N/A"),
            "network":      attrs.get("network", "N/A"),
            "reputation":   attrs.get("reputation", 0),
            "tags":         attrs.get("tags", []),
        }
        result.abip_data = abip_resp.get("data", {})
        result.verdict   = verdict_from_vt(stats)

        abuse_score = result.abip_data.get("abuseConfidenceScore", 0)
        if abuse_score >= 75 and result.verdict == "clean":
            result.verdict = "suspicious"
        if abuse_score >= 90:
            result.verdict = "malicious"

    except requests.HTTPError as e:
        result.error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result.error = str(e)

    return result

def enrich_hash(hash_val: str, vt: VirusTotalClient) -> IOCResult:
    result = IOCResult(ioc=hash_val, ioc_type="hash")
    try:
        vt_resp = vt.lookup_hash(hash_val)
        rate_limit()

        if not vt_resp:
            result.verdict  = "unknown"
            result.vt_data  = {}
            return result

        attrs = vt_resp.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.vt_data = {
            "stats":             stats,
            "meaningful_name":   attrs.get("meaningful_name", "N/A"),
            "type_description":  attrs.get("type_description", "N/A"),
            "size":              attrs.get("size", 0),
            "magic":             attrs.get("magic", "N/A"),
            "tags":              attrs.get("tags", []),
            "first_submission":  attrs.get("first_submission_date"),
            "last_submission":   attrs.get("last_submission_date"),
            "times_submitted":   attrs.get("times_submitted", 0),
            "popular_threat":    attrs.get("popular_threat_classification", {}),
        }
        result.verdict = verdict_from_vt(stats)

    except requests.HTTPError as e:
        result.error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result.error = str(e)

    return result

def _ts(epoch: Optional[int]) -> str:
    if not epoch:
        return "N/A"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def render_ip_section(r: IOCResult) -> str:
    vt   = r.vt_data
    abip = r.abip_data
    stats = vt.get("stats", {})

    abuse_score  = abip.get("abuseConfidenceScore", "N/A")
    total_reports = abip.get("totalReports", "N/A")
    usage_type   = abip.get("usageType", "N/A")
    isp          = abip.get("isp", "N/A")
    domain       = abip.get("domain", "N/A")
    last_seen    = abip.get("lastReportedAt", "N/A")

    lines = [
        f"### `{r.ioc}` — {VERDICT.get(r.verdict, r.verdict)}",
        "",
        "**VirusTotal**",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Malicious detections | {stats.get('malicious', 0)} |",
        f"| Suspicious detections | {stats.get('suspicious', 0)} |",
        f"| Harmless | {stats.get('harmless', 0)} |",
        f"| Undetected | {stats.get('undetected', 0)} |",
        f"| Country | {vt.get('country', 'N/A')} |",
        f"| ASN | {vt.get('asn', 'N/A')} — {vt.get('as_owner', 'N/A')} |",
        f"| Network | {vt.get('network', 'N/A')} |",
        f"| VT Reputation | {vt.get('reputation', 0)} |",
        f"| Tags | {', '.join(vt.get('tags', [])) or 'none'} |",
        "",
        "**AbuseIPDB**",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Abuse Confidence Score | {abuse_score}% |",
        f"| Total Reports (90 days) | {total_reports} |",
        f"| ISP | {isp} |",
        f"| Domain | {domain} |",
        f"| Usage Type | {usage_type} |",
        f"| Last Reported | {last_seen} |",
        "",
        f"**MITRE ATT&CK:** `{MITRE_MAP['ip']}`",
        "",
    ]
    return "\n".join(lines)

def render_hash_section(r: IOCResult) -> str:
    vt    = r.vt_data
    stats = vt.get("stats", {})
    pt    = vt.get("popular_threat", {})
    label = pt.get("suggested_threat_label", "N/A")

    if not vt:
        return (
            f"### `{r.ioc}` — {VERDICT['unknown']}\n\n"
            "_Not found in VirusTotal database._\n\n"
        )

    lines = [
        f"### `{r.ioc}` — {VERDICT.get(r.verdict, r.verdict)}",
        "",
        "**VirusTotal**",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Malicious detections | {stats.get('malicious', 0)} |",
        f"| Suspicious detections | {stats.get('suspicious', 0)} |",
        f"| Harmless | {stats.get('harmless', 0)} |",
        f"| Undetected | {stats.get('undetected', 0)} |",
        f"| File name | {vt.get('meaningful_name', 'N/A')} |",
        f"| File type | {vt.get('type_description', 'N/A')} |",
        f"| Magic | {vt.get('magic', 'N/A')} |",
        f"| Size | {vt.get('size', 0):,} bytes |",
        f"| First submission | {_ts(vt.get('first_submission'))} |",
        f"| Last submission | {_ts(vt.get('last_submission'))} |",
        f"| Times submitted | {vt.get('times_submitted', 0)} |",
        f"| Threat label | {label} |",
        f"| Tags | {', '.join(vt.get('tags', [])) or 'none'} |",
        "",
        f"**MITRE ATT&CK:** `{MITRE_MAP['hash']}`",
        "",
    ]
    return "\n".join(lines)


def generate_report(results: list[IOCResult], output_dir: str) -> str:
    now = datetime.now(tz=timezone.utc)
    ts  = now.strftime("%Y%m%d_%H%M%S")
    fname = Path(output_dir) / f"ioc_report_{ts}.md"

    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0, "error": 0}
    for r in results:
        if r.error:
            counts["error"] += 1
        else:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1

    lines = [
        "# IOC Enrichment Report",
        "",
        "## Executive Summary",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Report generated | {now.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Total IOCs analyzed | {len(results)} |",
        f"| Malicious | {counts['malicious']} |",
        f"| Suspicious | {counts['suspicious']} |",
        f"| Clean | {counts['clean']} |",
        f"| Unknown | {counts['unknown']} |",
        f"| Errors | {counts['error']} |",
        "",
        "## Threat Intelligence Sources",
        "",
        "- [VirusTotal](https://www.virustotal.com) — multi-engine AV scanning and network reputation",
        "- [AbuseIPDB](https://www.abuseipdb.com) — community-reported IP abuse database (90-day window)",
        "",
        "---",
        "",
        "## IOC Analysis",
        "",
    ]

    for r in results:
        if r.error:
            lines.append(f"### `{r.ioc}` — ❌ ERROR\n\n> {r.error}\n\n")
            continue
        if r.ioc_type == "ip":
            lines.append(render_ip_section(r))
        else:
            lines.append(render_hash_section(r))
        lines.append("---\n")

    lines += [
        "## Recommendations",
        "",
        "| Verdict | Recommended Action |",
        "|---|---|",
        "| Malicious | Block immediately at firewall/EDR. Open incident ticket. Pivot for related IOCs. |",
        "| Suspicious | Add to watchlist. Correlate with SIEM logs. Escalate if context confirms threat. |",
        "| Clean | No action required. Document for audit trail. |",
        "| Unknown | Manual review. Submit to VT sandbox if file. Monitor in SIEM. |",
        "",
        "## MITRE ATT&CK Coverage",
        "",
        "| IOC Type | Technique |",
        "|---|---|",
        "| IP Address | T1071 · T1041 · T1090 |",
        "| File Hash | T1204 · T1059 · T1027 |",
        "",
        "_Report generated by [ioc-enrichment](https://github.com/ges-cs01/ioc-enrichment)_",
    ]

    fname.write_text("\n".join(lines), encoding="utf-8")
    return str(fname)

def parse_args():
    p = argparse.ArgumentParser(
        description="IOC Enrichment Tool — VirusTotal + AbuseIPDB → Markdown report"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input",  help="Path to IOC file (one per line, # for comments)")
    group.add_argument("--ioc",          help="Single IOC to analyze (IP or hash)")
    p.add_argument("-o", "--output", default="reports/", help="Output directory for reports (default: reports/)")
    p.add_argument("--vt-key",   default=os.getenv("VT_API_KEY"),   help="VirusTotal API key (or set VT_API_KEY env var)")
    p.add_argument("--abip-key", default=os.getenv("ABIP_API_KEY"), help="AbuseIPDB API key (or set ABIP_API_KEY env var)")
    p.add_argument("--dry-run",  action="store_true", help="Detect IOC types only, do not call APIs")
    return p.parse_args()

def main():
    args = parse_args()

    if not args.dry_run:
        if not args.vt_key:
            sys.exit("VirusTotal API key missing. Set VT_API_KEY env var or use --vt-key.")
        if not args.abip_key:
            sys.exit("AbuseIPDB API key missing. Set ABIP_API_KEY env var or use --abip-key.")

    iocs = [args.ioc] if args.ioc else load_iocs_from_file(args.input)
    Path(args.output).mkdir(parents=True, exist_ok=True)

    vt   = VirusTotalClient(args.vt_key)   if not args.dry_run else None
    abip = AbuseIPDBClient(args.abip_key)  if not args.dry_run else None

    results = []
    for raw in iocs:
        ioc = raw.strip()
        ioc_type = detect_type(ioc)

        if not ioc_type:
            print(f"[SKIP] Unrecognized IOC format: {ioc}")
            continue

        print(f"[*] Analyzing {ioc_type.upper()}: {ioc}")

        if args.dry_run:
            results.append(IOCResult(ioc=ioc, ioc_type=ioc_type, verdict="unknown"))
            continue

        if ioc_type == "ip":
            result = enrich_ip(ioc, vt, abip)
        else:
            result = enrich_hash(ioc, vt)

        verdict_label = VERDICT.get(result.verdict, result.verdict)
        if result.error:
            print(f"     Error: {result.error}")
        else:
            print(f"    {verdict_label}")
        results.append(result)

    if not results:
        sys.exit("No valid IOCs found.")

    report_path = generate_report(results, args.output)
    print(f"\n  Report saved: {report_path}")


if __name__ == "__main__":
    main()
