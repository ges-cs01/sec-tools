# SIEM Use-Case Library

Detection rules for Wazuh mapped to MITRE ATT&CK, focused on Active Directory threat scenarios.

## Structure

Each rule lives in its own directory named `TXXXX.XXX-technique-name` under the relevant tactic folder.
Every directory contains:

| File | Purpose |
|---|---|
| `rule.xml` | Wazuh custom rule (drop into `/var/ossec/etc/rules/`) |
| `sigma.yml` | Sigma source rule (backend-agnostic, converts to any SIEM) |
| `README.md` | Technique context, required log sources, FP guidance, test steps |

## Coverage

### Credential Access
| ID | Technique | Status |
|---|---|---|
| T1558.003 | Kerberoasting | ✅ |
| T1558.004 | AS-REP Roasting | ✅ |
| T1003.001 | LSASS Memory Dump | ✅ |
| T1110.003 | Password Spraying | 🔲 |

### Lateral Movement
| ID | Technique | Status |
|---|---|---|
| T1550.002 | Pass-the-Hash | ✅ |
| T1021.002 | PsExec / SMB exec | ✅ |
| T1021.006 | WMI lateral movement | ✅ |
| T1543.003 | Remote service creation | 🔲 |

## Requirements

- Wazuh 4.x agent on Windows endpoints
- Windows Security audit policy:
  - `Audit Kerberos Service Ticket Operations` → Success + Failure
  - `Audit Kerberos Authentication Service` → Success + Failure
  - `Audit Logon Events` → Success + Failure
  - `Audit Process Creation` → Success (+ command line logging via GPO)
- Sysmon deployed with a hardened config (SwiftOnSecurity or Olaf Hartong recommended)

## Testing

Each rule README includes manual test steps using built-in Windows tools or:
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Impacket](https://github.com/fortra/impacket)
- [Rubeus](https://github.com/GhostPack/Rubeus)

## Lab environment

- Proxmox VE — Windows Server 2022 DC + Windows 10 workstation
- Wazuh 4.x manager + Elastic Stack
- Domain: `lab.local`

---

*[sec-tools](https://github.com/ges-cs01/sec-tools)*
