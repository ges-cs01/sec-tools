# T1550.002 — Pass-the-Hash

## What this detects

Pass-the-Hash (PtH) abuses NTLM authentication by using a captured NTLM hash
directly instead of a plaintext password. After dumping LSASS (T1003.001),
the attacker authenticates to remote services without knowing the actual password.

**Full attack chain in this lab:**
```
LSASS dump (T1003.001) → extract NTLM hash (pypykatz) → PtH (T1550.002) → PsExec shell (T1021.002) → WMI execution (T1047)
```

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Lateral Movement (TA0008), Defense Evasion (TA0005) |
| Technique | Use Alternate Authentication Material (T1550) |
| Sub-technique | Pass the Hash (T1550.002) |
| Data source | Windows Security Event Log — Event ID 4624 |

## Key detection indicator

Before, a null LogonGuid was used for detection, but very often NTLM logons produce a null LogonGuid (it is only populated by Kerberos). Relying on this field alone causes massive false positives. Instead, this detection relies on the subject context and workstation name:

| Indicator | Legitimate Windows NTLM | Pass-the-Hash / Impacket |
|---|---|---|
| subjectUserSid | Real SID (identifying the local process/session like svchost) | S-1-0-0 (NULL SID)
| workstationName | Populated (Windows SMB clients always send their hostname) | Blank or -

Tools like Impacket authenticate directly at the protocol level. Because there is no local Windows process initiating the auth, the subject context is S-1-0-0, and the workstation name is frequently left empty.

## Detection logic

| Rule | Level | Trigger |
|---|---|---|
| 100030 | 0 | Chains off 92652: subjectUserSid S-1-0-0 detected(silent base) |
| 100031 | 12 | S-1-0-0 + External source IP + non-machine account + blank workstationName |
| 100032 | 14 | Elevated token (%%1842) — privileged account targeted |

Wazuh built-in **92652** detects NTLM logon type 3 at level 6.
These rules add null SID, blank workstationName,  and privilege context on top.

Note: No single 4624 event gives a confirmed PtH alert. High-confidence detection requires chaining this behavior with PsExec and WMI execution (handled in T1021.002 and T1047 rules).

## Required log configuration

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## Test procedure

```bash
# Get NTLM hash from lsass dump
pypykatz lsa minidump lsass.dmp

# PtH with wmiexec — use IP not hostname (forces NTLM)
wmiexec.py <user>@<target_ip> -hashes :<NTLM_HASH>

# PtH with psexec
psexec.py <user>@<target_ip> -hashes :<NTLM_HASH>
```

### Validate

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered "pass_the_hash\|100031\|100032\|92652"
```

## False positives

| Source | Mitigation |
|---|---|
| Legitimate services using NULL SID | Whitelist by `targetUserName` or `ipAddress` in rule 100030 |
| Network scanners | Whitelist scanner IP |
| Machine accounts | Already filtered by `$` suffix negate in rule 100031 |
| Localhost NTLM | Already filtered by 127.0.0.1 / ::1 negate in rule 100031

## Response playbook (SOC L1)

1. **Identify** `targetUserName`, `ipAddress`, `elevatedToken` from alert.
2. **Check** if source IP is a known admin host or authorized scanner.
3. **Pivot** — was there an LSASS dump alert (100020-100023) before this?
4. **Check** for subsequent lateral movement — rules 100034/100037 (PsExec) and 100036/100038 (WMI) correlate automatically.
5. **Contain** — block source IP, disable compromised account, isolate hosts.
6. **Assume** all credentials on the source host are compromised.
7. **Escalate to L2** if elevated token — likely domain admin compromise.

## References

- [MITRE ATT&CK T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Event 4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Impacket wmiexec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)
