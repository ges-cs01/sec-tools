# Wazuh → DFIR-IRIS Integration

An automated alert ingestion pipeline that bridges **Wazuh SIEM/EDR** with the **DFIR-IRIS** Incident Response platform. High-severity or targeted security alerts detected by Wazuh are automatically pushed into the IRIS inbound alert triage queue.

---

## Features

- **Real-time Alert Forwarding** — Instantly pushes targeted security events from Wazuh agents to the IRIS API.
- **Defensive JSONL Parsing** — Handles both single-line automated inputs from the Wazuh daemon and multi-line testing logs.
- **Structured Payload Mapping** — Maps Wazuh severity levels, rule descriptions, and raw logs into the corresponding IRIS alert fields (`alert_title`, `alert_severity_id`, `alert_status_id`, etc.).

---

## Pipeline Architecture

```
[Adversarial Event]
        │
        ▼
[Wazuh Agent]  ──────────────────────────────────────────────────────────────────────
  Endpoint monitoring (Windows / Linux)                                              │
        │                                                                            │
        ▼                                                                            │
[Wazuh Manager]                                                                      │
  Aggregates event → writes to alerts.json                                          │
        │                                                                            │
        ▼                                                                            │
[wazuh-integratord]                                                                  │
  Matches Rule ID or severity → spawns custom-iris.py                               │
        │                                                                            │
        ▼                                                                            │
[custom-iris.py]                                                                     │
  Refines & maps payload → POST /alerts/add over HTTPS                              │
        │                                                                            │
        ▼                                                                            │
[DFIR-IRIS]  ────────────────────────────────────────────────────────────────────────
  Alert appears in inbound triage queue
```

1. **Detection** — An event (e.g., a network brute-force via Hydra) triggers a Wazuh rule on a monitored endpoint.
2. **Analysis** — The Wazuh Manager aggregates the event and writes it to `alerts.json`.
3. **Trigger** — `wazuh-integratord` reads the entry, matches the configured Rule ID or severity level, and spawns `custom-iris.py`.
4. **Ingestion** — The script refines the payload and POSTs it over HTTPS to the `/alerts/add` endpoint of your DFIR-IRIS instance.

---

## Installation & Configuration

### 1. Script Deployment

Place the integration script inside the standard Wazuh integrations directory:

```bash
sudo cp custom-iris.py /var/ossec/integrations/custom-iris.py
```

Set the correct ownership and permissions so the `wazuh` group can execute it:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py
sudo chmod 750 /var/ossec/integrations/custom-iris.py
```

### 2. Configure Wazuh Manager (`ossec.conf`)

Open `/var/ossec/etc/ossec.conf` and append the integration block. You can target specific high-priority Rule IDs (e.g., Windows Logon Failures `60122`, `60204`) or set a baseline alert level:

```xml
<ossec_config>
  <integration>
    <name>custom-iris.py</name>
    <rule_id>60122, 60204</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

Restart the Wazuh Manager to apply:

```bash
sudo systemctl restart wazuh-manager
```

### 3. Linux Kernel Security Adjustments (AppArmor)

Ubuntu's AppArmor profiles enforce tight baselines on Wazuh binaries. The `wazuh-integratord` daemon may be blocked from executing external scripts or making outbound network requests.

**Option A — Complain Mode (recommended for dev/lab environments):**

```bash
sudo apt install apparmor-utils -y
sudo aa-complain /var/ossec/bin/wazuh-integratord
```

**Option B — Explicit AppArmor rules** — Append the following to your AppArmor profile (`/etc/apparmor.d/usr.sbin.ossec-control` or equivalent):

```
/var/ossec/integrations/custom-iris.py rpx,
/var/ossec/framework/python/bin/python3* ix,
network tcp, 
```

---

## Verification & Testing

### Manual Mock Test

Simulate a Wazuh manager handoff by creating a mock JSON alert and running the script as the `wazuh` user:

```bash
# 1. Create a dummy alert file
echo '{"rule":{"level":10,"description":"Manual Integration Test Pipeline"},"full_log":"Testing IRIS API webhook pathway"}' > /tmp/test_alert.json

# 2. Execute the script as the wazuh user
sudo -u wazuh /var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-iris.py /tmp/test_alert.json
```

A successful run returns **HTTP 200 OK**, and the event appears immediately under the **Alerts** tab in your IRIS dashboard.

---

## Payload Mapping Reference

| Wazuh Field | IRIS Alert Field |
|---|---|
| `rule.description` | `alert_title` |
| `rule.level` | `alert_severity_id` |
| `full_log` | `alert_source_content` |
| *(static)* | `alert_status_id` |
| `agent.name` | `alert_source` |
| `timestamp` | `alert_source_event_time` |

---

## Notes

- **TLS/SSL** — Certificate validation is suppressed for self-signed certs in home lab environments. In production, replace with a properly trusted certificate and remove the `verify=False` flag from the HTTPS request.
- **AppArmor** — Complain Mode is appropriate for sandboxed development. Enforce mode with explicit rule entries is recommended for any environment beyond a personal lab.
- **Rule Targeting** — Using `<rule_id>` is preferred over a bare `<level>` threshold to reduce alert noise and avoid forwarding low-fidelity events to IRIS.
