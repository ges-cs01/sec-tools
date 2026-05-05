# IOC Enrichment Tool

Automated threat intelligence enrichment for IPs and file hashes. Queries **VirusTotal** and **AbuseIPDB**, cross-correlates results, and generates a structured Markdown report with MITRE ATT&CK mapping — ready to attach to a SOC incident ticket.

## Demo output

```
[*] Analyzing IP: 185.220.101.45
    MALICIOUS  (VT: 11 engines | AbuseIPDB: 100% confidence, 863 reports)

[*] Analyzing IP: 45.142.212.100
    SUSPICIOUS  (VT: 2 engines | AbuseIPDB: 68% confidence)

[*] Analyzing HASH: 92a3928d...
    SUSPICIOUS  (VT: hacktool.mimikatz/gen — 2 malicious, 5 suspicious)

   Report saved: reports/ioc_report_20250115_143200.md
```

→ See [`reports/sample_report.md`](reports/sample_report.md) for full report example.

## Features

- Detects IOC type automatically — IPv4, MD5, SHA256
- Queries VirusTotal v3 API (files + IP addresses endpoint)
- Queries AbuseIPDB with 90-day abuse window
- Cross-correlates both sources for a final verdict (malicious / suspicious / clean / unknown)
- Rate-limit safe — respects free tier limits (4 req/min VT)
- Generates timestamped Markdown report with executive summary and recommendations
- Maps findings to MITRE ATT&CK techniques

## Usage

```bash
# Set API keys
export VT_API_KEY="your_virustotal_key"
export ABIP_API_KEY="your_abuseipdb_key"

# Install dependencies
pip install -r requirements.txt

# Analyze a file of IOCs
python ioc_enrichment.py -i iocs/sample.txt -o reports/

# Analyze a single IOC
python ioc_enrichment.py --ioc 185.220.101.45
python ioc_enrichment.py --ioc 44d88612fea8a8f36de82e1278abb02f

# Dry run (no API calls — validates IOC types only)
python ioc_enrichment.py -i iocs/sample.txt --dry-run
```

## IOC input format

```text
# Comments are ignored
# Blank lines are ignored

# IPv4 addresses
185.220.101.45
193.32.162.157

# MD5 hashes
44d88612fea8a8f36de82e1278abb02f

# SHA256 hashes
92a3928dcc6cd7939f2b9e6c6f763dfa631e4902c0ca6fae0b5b7d1efd6f9f7e
```

## API keys (free tier)

| Source | Free tier | Get key |
|---|---|---|
| VirusTotal | 4 req/min, 500 req/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/register) |

## Tests

```bash
pytest tests/ -v
# 18 passed
```

## MITRE ATT&CK coverage

| IOC Type | Technique |
|---|---|
| IP Address | T1071 · T1041 · T1090 |
| File Hash | T1204 · T1059 · T1027 |
