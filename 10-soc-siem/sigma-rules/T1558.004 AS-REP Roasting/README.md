# T1558.004 — AS-REP Roasting

## What this detects

AS-REP Roasting targets Active Directory accounts that have **"Do not require Kerberos preauthentication"** enabled (`DONT_REQ_PREAUTH` / `UF_DONT_REQUIRE_PREAUTH` flag). When this flag is set, the DC will respond to an AS-REQ with an AS-REP encrypted with the account's NTLM hash — without verifying the requester's identity first. The attacker takes the encrypted blob offline and cracks it (Hashcat mode 18200).

**Key difference from Kerberoasting:**

| | Kerberoasting (T1558.003) | AS-REP Roasting (T1558.004) |
|---|---|---|
| Requires valid creds | Yes | No |
| Target | Accounts with SPNs | Accounts with DONT_REQ_PREAUTH |
| Event ID | 4769 (TGS-REQ) | 4768 (AS-REQ) |
| Hashcat mode | 13100 | 18200 |

## ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | Steal or Forge Kerberos Tickets (T1558) |
| Sub-technique | AS-REP Roasting (T1558.004) |
| Data source | DS0026 — Active Directory: Active Directory Credential Request |
| Log source | Windows Security Event Log |
| Event ID | **4768** — A Kerberos authentication ticket (TGT) was requested |

## Required log configuration

```cmd
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

GPO path:
`Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Account Logon → Audit Kerberos Authentication Service`

Confirm:
```cmd
auditpol /get /subcategory:"Kerberos Authentication Service"
```

## Key fields in Event 4768

| Field | AS-REP Roasting indicator |
|---|---|
| `PreAuthType` | `0` = no preauthentication — core indicator |
| `Status` | `0x0` = success (DC handed out the ticket) |
| `TicketEncryptionType` | `0x17` = RC4 (attacker preference); `0x12` = AES |
| `TargetUserName` | The targeted account |
| `IpAddress` | Source of the request |

## Detection logic

Three-level cascade:

1. **100010 (level 12)** — Any 4768 with `PreAuthType=0` and success status. Broad catch.
2. **100011 (level 14)** — Same, filtered to RC4 encryption. Near-certain malicious.
3. **100012 (level 15)** — 3+ hits from same IP in 60s. Automated enumeration confirmed.

## Lab setup — create a vulnerable account

```powershell
# Create the account
New-ADUser -Name "asrepuser" -SamAccountName "asrepuser" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true

# Set DONT_REQ_PREAUTH
Set-ADAccountControl -Identity "asrepuser" -DoesNotRequirePreAuth $true

# Confirm
Get-ADUser asrepuser -Properties DoesNotRequirePreAuth | Select-Object Name, DoesNotRequirePreAuth
```

## Test procedure

### Option 1 — Impacket GetNPUsers.py

```bash
# Enumerate and request AS-REP for all DONT_REQ_PREAUTH accounts
GetNPUsers.py lab.local/ -usersfile /tmp/users.txt -no-pass -dc-ip <DC_IP> -outputfile asrep_hashes.txt

# Or target directly if you know the username
GetNPUsers.py lab.local/asrepuser -no-pass -dc-ip <DC_IP>

# Crack offline
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

Create `/tmp/users.txt` with one username per line to enumerate.

### Option 2 — Rubeus (from domain-joined Windows)

```powershell
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt
```

### Option 3 — Atomic Red Team

```powershell
Invoke-AtomicTest T1558.004
```

### Validation steps

1. Run the attack from.
2. On DC: Event Viewer → Security → filter Event ID 4768, check `Pre-Authentication Type: 0`.
3. On Wazuh manager: `sudo tail -f /var/ossec/logs/alerts/alerts.json | grep asreproast`

## False positives

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Legacy app needing DONT_REQ_PREAUTH | Low | Whitelist `TargetUserName` in rule 100010 |
| Localhost requests (::1) | Medium | Sigma rule filters `::1` source; add to Wazuh rule if needed |

**Hardening:** run this monthly to audit accounts with the flag set:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName, Enabled
```

Any account that doesn't need the flag — remove it:

```powershell
Set-ADAccountControl -Identity "username" -DoesNotRequirePreAuth $false
```

## Response playbook (SOC L1)

1. **Identify** `TargetUserName` and `IpAddress` from the alert.
2. **Check** if the account legitimately needs `DONT_REQ_PREAUTH` — it almost never does.
3. **Pivot** — did the source IP make other suspicious requests? Check 4768/4769 history.
4. **Contain** — disable the account if compromise suspected; force password reset.
5. **Harden** — remove `DONT_REQ_PREAUTH` flag from the account immediately.
6. **Escalate to L2** if cracked password is suspected or lateral movement observed.

## References

- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Microsoft — Event 4768](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Harmj0y — Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Impacket GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
