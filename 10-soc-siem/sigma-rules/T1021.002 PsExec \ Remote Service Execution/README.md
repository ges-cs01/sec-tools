# T1021.002 — PsExec / Remote Service Execution

## What this detects

PsExec and Impacket's psexec.py move laterally by copying a service binary
to the target via SMB (ADMIN$ share), creating a remote service (Event 7045),
and executing commands through named pipes.

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Lateral Movement (TA0008) |
| Technique | Remote Services (T1021) |
| Sub-technique | SMB/Windows Admin Shares (T1021.002) |
| Also covers | System Services: Service Execution (T1569.002) |
| Data source | Windows System Event Log — Event ID 7045 |

## Impacket psexec.py signature

```
serviceName: random 4-char string (TTGL, gvIi, XkPm...)
imagePath:   %systemroot%\<random>.exe
accountName: LocalSystem
startType:   demand start
```

## Detection logic

| Rule | Level | Trigger |
|---|---|---|
| 100033 | 14 | Chains off 92650: suspicious service created from %systemroot% |
| 100034 | 15 | PsExec (100033) within 120s after PtH (100031/100032) |
| 100037 | 15 | PtH (100031/100032) within 120s after PsExec (100033) |

Rules 100034 and 100037 are bidirectional — handles log ingestion timing
differences where either alert can arrive first.

Wazuh built-in **92650** detects the service creation pattern.
Rule 100033 adds MITRE tagging. Rules 100034/100037 are the chain detection.

## Test procedure

```bash
psexec.py <user>@<IP> -hashes :<NTLM_HASH>
```

### Validate

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered "psexec\|100033\|100034\|100037\|92650"
```

## Attack chain alert (100034 / 100037)

Fires when PtH + PsExec are detected on the same target within 120 seconds.
This is the strongest lateral movement indicator in this rule set —
two complementary techniques, one correlated alert.

## Response playbook (SOC L1)

1. **Identify** service name and imagePath from the 7045 event.
2. **Check** if a PtH alert (100031/100032) preceded — rules 100034/100037 correlate automatically.
3. **Pivot** — what account created the service and where did it authenticate from?
4. **Contain** — stop and delete the remote service, isolate the target host.
5. **Hunt** — check all hosts for the same random service name pattern.
6. **Escalate** if 100034/100037 fired — full attack chain confirmed, treat as active IR.

## References

- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [Impacket psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- [Microsoft Event 7045](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn408187(v=ws.11))
