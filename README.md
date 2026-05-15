# sec-tools

A collection of security engineering tools and detection content for SOC / SIEM workflows, built around a home lab running Wazuh, Elastic Stack, and DFIR-IRIS.

## Repository layout

```
sec-tools/
└── 10-soc-siem/
    ├── ioc-enrichment/              # Automated IOC enrichment & reporting
    ├── sigma-rules/                 # MITRE ATT&CK–mapped Wazuh / Sigma detection rules
    └── wazuh-dfir-iris-integration/ # Wazuh → DFIR-IRIS alert ingestion pipeline
```

## Projects

### [IOC Enrichment](10-soc-siem/ioc-enrichment/)

Automated threat intelligence enrichment for IPs and file hashes. Queries **VirusTotal** and **AbuseIPDB**, cross-correlates results, and generates a timestamped Markdown report with MITRE ATT&CK mapping — ready to attach to a SOC incident ticket.

**Highlights**
- Detects IOC type automatically (IPv4, MD5, SHA256)
- Cross-correlates VirusTotal and AbuseIPDB for a final verdict (malicious / suspicious / clean / unknown)
- Rate-limit safe (respects VirusTotal free-tier limits)
- Maps findings to MITRE ATT&CK techniques (T1071, T1041, T1204, …)

```bash
export VT_API_KEY="<key>"
export ABIP_API_KEY="<key>"
pip install -r 10-soc-siem/ioc-enrichment/requirements.txt
python 10-soc-siem/ioc-enrichment/ioc_enrichment.py -i iocs/sample.txt
```

---

### [SIEM Use-Case Library (Sigma / Wazuh)](10-soc-siem/sigma-rules/)

Detection rules for Wazuh mapped to MITRE ATT&CK, focused on Active Directory threat scenarios. Each rule ships in three formats:

| File | Purpose |
|---|---|
| `rule.xml` | Wazuh custom rule (drop into `/var/ossec/etc/rules/`) |
| `sigma.yml` | Backend-agnostic Sigma rule (converts to any SIEM) |
| `README.md` | Technique context, log-source requirements, FP guidance, test steps |

**Current coverage**

| ID | Technique | Status |
|---|---|---|
| T1558.003 | Kerberoasting | ✅ |
| T1558.004 | AS-REP Roasting | 🔲 |
| T1003.001 | LSASS Memory Dump | 🔲 |
| T1110.003 | Password Spraying | 🔲 |
| T1550.002 | Pass-the-Hash | 🔲 |
| T1021.002 | PsExec / SMB exec | 🔲 |

---

### [Wazuh → DFIR-IRIS Integration](10-soc-siem/wazuh-dfir-iris-integration/)

A lightweight integration script (`custom-iris.py`) that bridges **Wazuh SIEM/EDR** with the **DFIR-IRIS** incident response platform. High-severity or targeted Wazuh alerts are automatically pushed to the IRIS inbound alert triage queue in real time.

**Pipeline**

```
Adversarial Event → Wazuh Agent → Wazuh Manager → wazuh-integratord → custom-iris.py → DFIR-IRIS
```

**Quick deploy**

```bash
sudo cp 10-soc-siem/wazuh-dfir-iris-integration/custom-iris.py /var/ossec/integrations/
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py
sudo chmod 750 /var/ossec/integrations/custom-iris.py
sudo systemctl restart wazuh-manager
```

---

## Lab environment

- **Hypervisor** — Proxmox VE
- **Endpoints** — Windows Server 2022 DC + Windows 10 workstation (`lab.local`)
- **SIEM/EDR** — Wazuh 4.x manager + Elastic Stack
- **IR platform** — DFIR-IRIS

## License

See individual project directories for licensing details.
