# T1047 — WMI Remote Execution

## What this detects

Impacket wmiexec.py executes commands remotely via Windows Management
Instrumentation (WMI). Unlike PsExec, it doesn't create a service or
drop a binary — it uses WMI to spawn cmd.exe on the target, making it
harder to detect with traditional service-based rules.

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Lateral Movement (TA0008), Execution (TA0002) |
| Technique | Windows Management Instrumentation (T1047) |
| Data source | Sysmon Event ID 1 (Process Create) |

## Impacket wmiexec.py signature

```
parentImage:  C:\Windows\System32\wbem\WmiPrvSE.exe
image:        C:\Windows\System32\cmd.exe
commandLine:  cmd.exe /Q /c <command> 1> \\127.0.0.1\... 2>&1
```

The `/Q` flag (echo off) + `/c` + `WmiPrvSE.exe` parent is a near-unique
indicator of Impacket wmiexec.py behavior.

## Detection logic

| Rule | Level | Trigger |
|---|---|---|
| 100035 | 14 | WmiPrvSE.exe spawns cmd.exe with /Q /c flags (Sysmon Event 1) |
| 100036 | 15 | WMI exec (100035) within 120s after PtH (100031/100032) |
| 100038 | 15 | PtH (100031/100032) within 120s after WMI exec (100035) |

Rules 100036 and 100038 are bidirectional — same timing-resilient pattern
as the PsExec chain rules.

## Required setup

Sysmon must be collecting process creation events (Event 1) on the target.
In `ossec.conf` on the target agent:

```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
```

## Test procedure

```bash
# PtH + WMI execution in one command
wmiexec.py <user>@<IP> -hashes :<NTLM_HASH>
```

### Validate

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered "wmiexec\|100035\|100036\|100038"
```

## False positives

| Source | Mitigation |
|---|---|
| Legitimate WMI admin scripts | Check parentImage + commandLine together |
| SCCM/ConfigMgr deployments | Whitelist by sourceUser or parentCommandLine |

The `/Q /c` flag combination narrows FPs significantly — legitimate WMI
scripts rarely use echo-off mode with output redirection.

## Response playbook (SOC L1)

1. **Identify** commandLine and user from the Sysmon Event 1 alert.
2. **Check** if a PtH alert preceded — rules 100036/100038 correlate automatically.
3. **Pivot** — what commands were executed? Check subsequent Sysmon Event 1 children of that cmd.exe.
4. **Contain** — isolate the target host, block the source IP.
5. **Hunt** — search for other hosts with WmiPrvSE spawning cmd.exe in the same timeframe.
6. **Escalate** if 100036/100038 fired — active lateral movement confirmed.

## References

- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [Impacket wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)
- [Sysmon Event ID 1](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
