# T1003.001 — LSASS Memory Dump

## What this detects

LSASS (Local Security Authority Subsystem Service) stores credential material in memory:
NTLM hashes, Kerberos tickets, and cleartext passwords (WDigest, if enabled).
Attackers dump lsass.exe memory to extract these credentials offline.

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | OS Credential Dumping (T1003) |
| Sub-technique | LSASS Memory (T1003.001) |
| Data sources | Sysmon Event 1 (Process Create), Sysmon Event 10 (Process Access) |

## Detection coverage

| Technique | Tool | Detection | Rule | Notes |
|---|---|---|---|---|
| comsvcs.dll MiniDump | rundll32 (LOLBin) | Sysmon Event 1 | 100020 | Covers MiniDump and #24 ordinal |
| comsvcs.dll ordinal bypass | rundll32,#24 | Sysmon Event 1 | 100020 | Evasion variant, same rule |
| ProcDump | procdump.exe | Sysmon Event 1 | 100021 | |
| Renamed ProcDump | any.exe -ma lsass | Sysmon Event 1 | 100021 | Catches binary rename evasion |
| Mimikatz | sekurlsa::logonpasswords | Sysmon Event 10 | 100023 | Access mask 0x1010 |
| PowerShell direct access | custom scripts | Sysmon Event 10 |  100023 | Built-in rule also fires |

## Detection logic

Four rules across two Sysmon event types:

| Rule | Level | Trigger | Notes |
|---|---|---|---|
| 100020 | 14 | Event 1: comsvcs + MiniDump or #24 in commandLine | Covers ordinal bypass |
| 100021 | 14 | Event 1: lsass + procdump/dumpert/sqldumper/-ma | Catches renamed binaries |
| 100022 | 0 | Event 10: lsass access with 0x1xxx mask | Silent base filter, no alert |
| 100023 | 15 | Event 10: known malicious access masks, excludes Defender | High confidence |

## Wazuh implementation notes

- Use `<if_group>sysmon_event_10</if_group>` for Event 10 rules — more robust than
  `<if_sid>61610</if_sid>`, avoids eventchannel parent ID mismatch.
- Rule 100022 is `level="0"` — silent base filter, exists only as parent for 100023.
- `MsMpEng.exe` excluded from 100023 — Windows Defender opens lsass with high
  access rights legitimately, causing constant FPs without this exclusion.

## Required setup

### Sysmon config — ProcessAccess rule

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

Apply:
```cmd
sysmon64.exe -c sysmonconfig.xml
```

### Wazuh agent — Sysmon channel

In `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
```

### Drop rule file

```bash
sudo cp local_lsass_rules.xml /var/ossec/etc/rules/local_lsass_rules.xml
sudo systemctl restart wazuh-manager
```

## Test procedure

### Option 1 — comsvcs.dll MiniDump (triggers 100020)

```powershell
$id = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $id C:\Windows\Temp\lsass.dmp full
```

### Option 2 — ProcDump (triggers 100021)

```cmd
procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

### Option 3 — PowerShell Process Access (triggers 100023)

```powershell
$proc = Get-Process lsass
$handle = $proc.Handle
```


### Option 4 — Task Manager (triggers 100023)

Right-click `lsass.exe` in Task Manager -> Details tab -> Create dump file.


### Validate

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered "lsass\|100020\|100021\|100023"
```

## False positives

| Source | Access Mask | Mitigation |
|---|---|---|
| Windows Defender (C:\\...\MsMpEng.exe) | 0x1fffff | Already excluded in rule 100023 |
| EDR/AV products | varies | Whitelist by sourceImage |
| Windows Error Reporting (WerFault.exe) | 0x1fffff | Add negate if noisy |
| Legitimate crash dump tools | varies | Coordinate with change management |

## Response playbook (SOC L1)

1. **Identify** sourceImage and user from the alert.
2. **Check** if it's a known AV/EDR or authorized admin tool.
3. **Pivot** — what ran before this? Check Event 1 history for the parent process.
4. **Assume credential compromise** if dump confirmed — escalate to L2 immediately.
5. **Contain** — isolate the host, block outbound traffic.
6. **Force password resets** for all accounts that were logged on to that host.
7. **Check lateral movement** — Event 4624 logon type 3 from that host IP after the dump time.

## References

- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [LOLBAS — comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/)
- [Sysmon Event ID 10](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [comsvcs.dll ordinal bypass](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
