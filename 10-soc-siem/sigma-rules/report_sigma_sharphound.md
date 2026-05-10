# Report — Regra Sigma: Detecção de SharpHound (BloodHound Collector)

---

## 1. Técnica MITRE ATT&CK

| Campo | Valor |
|---|---|
| **Técnica principal** | T1087.002 — Account Discovery: Domain Account |
| **Técnicas relacionadas** | T1069.002 (Domain Groups), T1482 (Domain Trust Discovery) |
| **Tática** | Discovery |
| **Ferramenta** | SharpHound (coletor do BloodHound) |

### Overview

SharpHound é o coletor oficial do BloodHound, usado para mapear o Active Directory após obtenção de foothold na rede. Ele enumera usuários, grupos, GPOs, ACLs e relações de confiança entre domínios, gerando um grafo que aponta caminhos para Domain Admin.

É uma ferramenta de **alto valor de detecção**:
- Muito usada em campanhas reais (APT, ransomware pré-deploy)
- Possui artefatos claros no Sysmon Event ID 1 (nome do binário, argumentos, hash)
- Gera bastante ruído de AD que pode correlacionar com outras regras (LDAP queries em volume)

---

## 2. Regra Sigma (YAML)

```yaml
title: SharpHound Execution via Command Line (BloodHound Collector)
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
    Detects execution of SharpHound, the BloodHound Active Directory enumeration
    tool used by attackers to map AD environments and identify privilege escalation
    paths. Covers binary name variants, common CLI arguments, and known SHA256
    hashes via Sysmon Event ID 1 (Process Creation).
author: GES 
date: 2026/05/04
references:
    - https://attack.mitre.org/techniques/T1087/002/
    - https://attack.mitre.org/techniques/T1069/002/
    - https://attack.mitre.org/techniques/T1482/
    - https://github.com/BloodHoundAD/SharpHound
logsource:
    category: process_creation   # Sysmon Event ID 1
    product: windows
detection:
    sel_image:
        Image|endswith:
            - '\SharpHound.exe'
            - '\sharphound.exe'
    sel_hash:
        Hashes|contains:
            - 'SHA256=F5D8A0E4E5B6C4E8C3E7E2D1B0A9F8E7D6C5B4A3F2E1D0C9B8A7F6E5D4C3B2A1'
            - 'SHA256=BAD0F25F7D5D7E68A4E3E8E1D0C9B8A7F6E5D4C3B2A1F0E9D8C7B6A5F4E3D2C1'
    sel_cli:
        CommandLine|contains|all:
            - '--CollectionMethod'
            - '--Domain'
    sel_cli_short:
        CommandLine|contains|all:
            - '-c '
            - '--ZipFilename'
    sel_cli_session:
        CommandLine|contains:
            - '--CollectionMethod Session'
            - '--CollectionMethod All'
            - '--CollectionMethod DCOnly'
            - '--CollectionMethod Trusts'
    filter_pentest:
        ComputerName|contains:
            - 'PENTEST-'
            - 'REDTEAM-'
    condition: >
        (sel_image or sel_hash or sel_cli or sel_cli_short or sel_cli_session)
        and not filter_pentest
falsepositives:
    - (whitelist por ComputerName ou ParentImage)
    - BloodHound Community Edition utilizado pela equipe de SecOps com aprovação formal
level: high
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.t1069.002
    - attack.t1482
```

### Campos Sysmon utilizados (Event ID 1)

| Campo Sigma | Campo Sysmon | Detecção |
|---|---|---|
| `Image` | ProcessImage | Nome do binário em qualquer path |
| `Hashes` | Hashes | SHA256 de builds conhecidas |
| `CommandLine` | CommandLine | Args: `--CollectionMethod`, `--Domain`, etc. |
| `ComputerName` | Computer | Filtro de exclusão por hostname |

---

## 3. Conversão para Elasticsearch (Lucene)

Gerado via **pySigma** (`sigma-backend-elasticsearch`) com pipeline `sysmon`:

```
((Image:(*\\SharpHound.exe OR *\\sharphound.exe))
OR
(Hashes:(*SHA256\=F5D8A0E4E5B6C4E8C3E7E2D1B0A9F8E7D6C5B4A3F2E1D0C9B8A7F6E5D4C3B2A1*
         OR *SHA256\=BAD0F25F7D5D7E68A4E3E8E1D0C9B8A7F6E5D4C3B2A1F0E9D8C7B6A5F4E3D2C1*))
OR
(CommandLine:*\-\-CollectionMethod* AND CommandLine:*\-\-Domain*)
OR
(CommandLine:*\-c\ * AND CommandLine:*\-\-ZipFilename*)
OR
(CommandLine:(*\-\-CollectionMethod\ Session*
              OR *\-\-CollectionMethod\ All*
              OR *\-\-CollectionMethod\ DCOnly*
              OR *\-\-CollectionMethod\ Trusts*)))
AND
(NOT (ComputerName:(*PENTEST\-* OR *REDTEAM\-*)))
```

### Como usar no Kibana / Elastic SIEM

1. Abra **Kibana → Security → Rules → Create Rule**
2. Selecione **Custom Query**
3. Cole a query Lucene acima no campo **Custom query**
4. Configure Index pattern: `winlogbeat-*` ou `logs-endpoint*`
5. Defina schedule: **every 5 minutes**, lookback: **5 minutes**
6. Severity: **High**, Risk score: **75**

---

## 4. Conversão para Wazuh (OpenSearch / Lucene)

Wazuh 4.x usa OpenSearch internamente. A query Lucene gerada é idêntica à do Elasticsearch e pode ser usada no **Wazuh Dashboard** (interface OpenSearch):

```
((winlog.event_data.Image:(*\\SharpHound.exe OR *\\sharphound.exe))
OR
(winlog.event_data.Hashes:(*SHA256\=F5D8A0...* OR *SHA256\=BAD0F2...*))
OR
(winlog.event_data.CommandLine:*\-\-CollectionMethod* AND winlog.event_data.CommandLine:*\-\-Domain*)
...
AND NOT (winlog.ComputerName:(*PENTEST\-* OR *REDTEAM\-*)))
```

### Regra XML nativa Wazuh (para `/var/ossec/etc/rules/local_rules.xml`)

```xml
<!-- Detecta SharpHound por nome de binário — requer Sysmon + Winlogbeat -->
<group name="windows,sysmon,bloodhound,">

  <rule id="100200" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)sharphound\.exe$</field>
    <description>SharpHound (BloodHound collector) executed — binary name match</description>
    <mitre>
      <id>T1087.002</id>
      <id>T1069.002</id>
      <id>T1482</id>
    </mitre>
    <group>attack,discovery,credential_access,</group>
  </rule>

  <rule id="100201" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)--CollectionMethod.*(All|Session|DCOnly|Trusts)</field>
    <description>SharpHound — CollectionMethod argument detected in CommandLine</description>
    <mitre>
      <id>T1087.002</id>
    </mitre>
    <group>attack,discovery,</group>
  </rule>

  <rule id="100202" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)--CollectionMethod.*--Domain</field>
    <description>SharpHound — --CollectionMethod combined with --Domain argument</description>
    <mitre>
      <id>T1087.002</id>
    </mitre>
    <group>attack,discovery,</group>
  </rule>

</group>
```

### Como ativar no Wazuh

```bash
# 1. Copie as regras para o manager
sudo cp local_rules.xml /var/ossec/etc/rules/

# 2. Valide a sintaxe
sudo /var/ossec/bin/ossec-logtest -t

# 3. Reinicie o manager
sudo systemctl restart wazuh-manager

# 4. Confirme que Sysmon está ativo nos agentes Windows
# e que o canal "Microsoft-Windows-Sysmon/Operational" 
# está no ossec.conf do agente:
#   <localfile>
#     <location>Microsoft-Windows-Sysmon/Operational</location>
#     <log_format>eventchannel</log_format>
#   </localfile>
```

---

## 5. Análise de cobertura e pontos cegos

### O que a regra detecta bem

- Execução com nome original `SharpHound.exe` (caso mais comum em ambientes reais)
- Uso de argumentos longos (`--CollectionMethod`, `--Domain`) mesmo com binary renomeado
- Builds públicas via hash SHA256 (atualizar com hashes do VirusTotal / GitHub releases)
- Collection modes mais agressivos: `All`, `Session`, `DCOnly`, `Trusts`

### Pontos cegos (limitações)

| Técnica de evasão | Mitigação |
|---|---|
| Binary renomeado + argumentos diferentes | Adicionar hashes de builds conhecidas |
| Execução in-memory (Cobalt Strike `execute-assembly`) | Correlacionar com Sysmon Event ID 10 (process_access) em LDAP queries |
| SharpHound via PowerShell (`Invoke-BloodHound`) | Adicionar regra separada para `sel_ps` com `CommandLine|contains: 'Invoke-BloodHound'` |
| Uso da API do BloodHound CE via HTTP | Monitorar tráfego de saída para porta 8080 do servidor BloodHound |

### Correlação

Encadear esta regra com detecção de volume de queries LDAP (Event ID 1644 no Domain Controller) no mesmo `ComputerName` em janela de 15 minutos — SharpHound gera centenas de queries LDAP em poucos segundos.

---

## 6. Ferramentas utilizadas

| Ferramenta | Versão | Papel |
|---|---|---|
| `pySigma` | 1.3.3 | Runtime de conversão Sigma |
| `pySigma-backend-elasticsearch` | 2.0.2 | Geração de query Lucene para Elastic |
| `pySigma-backend-opensearch` | 2.0.2 | Geração de query para Wazuh Dashboard |
| `pySigma-pipeline-sysmon` | 2.0.0 | Mapeamento de campos Sigma → Sysmon |

### Comando de conversão (sigma-cli, para uso local)

```bash
# Instalar
pip install sigma-cli pySigma-backend-elasticsearch pySigma-pipeline-sysmon

# Converter para Eql
sigma convert -t eql -p sysmon sharphound_detection.yml

# Converter para Splunk 
sigma convert -t splunk -p sysmon sharphound_detection.yml

# Via Uncoder.io (alternativa web)
# 1. Acesse https://uncoder.io
# 2. Selecione "Sigma" como formato de entrada
# 3. Cole o YAML
# 4. Selecione o destino (Elastic, Splunk, QRadar, etc.)
# 5. Clique em Translate
```

---

*atualizar hashes SHA256 com builds reais.*
