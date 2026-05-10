# T1558.003 — Kerberoasting

## What this detects

Kerberoasting is a credential access technique where an attacker with any valid domain account requests Kerberos TGS (service) tickets for accounts that have SPNs (Service Principal Names) registered. The tickets are encrypted with the service account's NTLM hash and can be taken offline for cracking without touching the target machine or generating lockouts.

**Why RC4?** By default, Windows will honour an RC4 (etype 0x17) encryption request even if the DC supports AES. RC4 hashes are drastically faster to crack (Hashcat mode 13100). Tools like Rubeus and Impacket's `GetUserSPNs.py` request RC4 deliberately for this reason.

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | Steal or Forge Kerberos Tickets (T1558) |
| Sub-technique | Kerberoasting (T1558.003) |
| Data source | DS0026 — Active Directory: Active Directory Credential Request |
| Log source | Windows Security Event Log |
| Event ID | **4769** — A Kerberos service ticket was requested |

## Required log configuration

On your Domain Controller, enable via GPO or `auditpol`:

```
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

Or GPO path:
`Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Account Logon → Audit Kerberos Service Ticket Operations`

Confirm with:
```
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

## Key fields in Event 4769

| Field | Kerberoasting indicator |
|---|---|
| `Ticket Encryption Type` | `0x17` (RC4-HMAC) — suspicious; `0x12` (AES256) is normal |
| `Ticket Options` | `0x40810000` — standard TGS request flags |
| `Service Name` | The SPN target — watch for user accounts, not `HOSTNAME$` |
| `ipAddress` | Source IP — correlate with workstation |
| `Account Name` | Requesting user — any domain user can do this |

## Detection logic

Three-level rule cascade:

1. **100001 (level 12)** — Any 4769 with etype `0x17` and standard ticket options.
2. **100002 (level 14)** — Same, filtered to exclude machine accounts (`$` suffix) and `krbtgt` using PCRE2 regex on `win.eventdata.serviceName`. Higher confidence
3. **100003 (level 15)** — 3+ RC4 TGS requests from same source IP in 60 seconds (correlated from rule 100002). Near-certain automated tooling.

## False positives

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Legacy app using RC4 | Low–Medium | Whitelist `ServiceName` and `ipAddress` in rule 100001 |
| Old Windows clients | Very Low | These shouldn't exist in a patched AD |
| Legitimate pen test | Medium | Coordinate with change management; suppress by IP during window |

**Tuning tip:** Run this query on 7 days of logs before enabling alerting to baseline your RC4 TGS volume:

Lucene (Elastic):
```
event.code:4769 AND winlog.event_data.TicketEncryptionType:"0x17"
```

Any recurring `ServiceName` that appears legitimately → add to filter.

## Test procedure (in your lab)

### Option 1 — Impacket (from Kali/attacker VM)

```bash
# Install impacket if needed
pip install impacket

# Request all TGS tickets for SPNs in the domain
GetUserSPNs.py lab.local/lowpriv:Password123 -dc-ip 192.168.x.x -request -outputfile hashes.txt

# Crack offline
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Option 2 — Rubeus (from domain-joined Windows)

```powershell
# Download Rubeus or compile from source
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

### Option 3 — Atomic Red Team

```powershell
# Requires AtomicRedTeam module
Invoke-AtomicTest T1558.003
```

### Validation steps

1. Run one of the above on your attacker VM.
2. On the DC, open Event Viewer → Windows Logs → Security → filter for Event ID 4769.
3. Confirm `Ticket Encryption Type` = `0x17` and `Service Name` is a user account (not `HOSTNAME$`).
4. In Wazuh dashboard, verify alert fires at level 12+ with group `kerberoasting`.

## Response playbook (SOC L1)

1. **Identify** the `ipAddress` (source) and `Account Name` (requesting user).
2. **Check** if the source IP is a known pen test host or authorized scanner.
3. **Pivot** — did this account make other suspicious requests? Check logon events (4624) and process creation (4688/Sysmon 1) on the source host.
4. **Escalate to L2** if: source is unexpected, multiple service names targeted, or cracking attempt detected on the wire (monitor outbound traffic to known cracking IPs).
5. **Contain** — disable the requesting account if malicious intent confirmed; rotate SPN account passwords.

## References

- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [HarmJ0y — Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Microsoft — Event 4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [SpecterOps — Detecting Kerberoasting](https://posts.specterops.io/detecting-kerberoasting-activity-807686f89d93)
