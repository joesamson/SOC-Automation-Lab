# SOC Automation Lab
### Building a Complete SOC Automation Pipeline with Wazuh, Sysmon, Shuffle SOAR, VirusTotal, and TheHive on AWS
From endpoint telemetry to automated incident tickets — a fully automated detection-to-response pipeline

`Wazuh` `Sysmon` `Shuffle SOAR` `VirusTotal` `TheHive` `AWS` `MITRE ATT&CK` `SOC`



## Project Overview
This project demonstrates the design, deployment, and automation of a Security Operations Center (SOC) environment using open-source technologies and AWS cloud infrastructure.

The goal was to simulate a real-world enterprise SOC capable of:

- Collecting endpoint telemetry
- Detecting malicious activity
- Enriching indicators with threat intelligence
- Automatically generating incident tickets
- Notifying analysts with minimal manual intervention

This project was built as part of a SOC Analyst and Detection Engineering learning journey and focuses on practical, hands-on implementation rather than theory.

## Project Objectives
- Deploy Wazuh Manager, Indexer, and Dashboard on AWS
- Collect endpoint telemetry with Sysmon
- Engineer custom Wazuh detection rules
- Automate alert forwarding with Shuffle SOAR
- Enrich indicators of compromise using VirusTotal
- Automatically create incident tickets in TheHive
- Deliver analyst notifications with minimal manual intervention

## Pipeline Architecture
| Stage | Component |
|---|---|
| Endpoint | Windows 11 + Sysmon |
| Log Shipping | Wazuh Agent |
| SIEM / Detection | Wazuh Manager |
| Orchestration | Shuffle SOAR |
| Threat Intel Enrichment | VirusTotal |
| Case Management | TheHive |

```
Windows 11 Endpoint → Sysmon → Wazuh Agent → Wazuh Manager → Shuffle SOAR → VirusTotal → TheHive
```

## Deployment Phases

### Phase 1–3: Wazuh Deployment
```bash
chmod +x wazuh-install.sh
sudo ./wazuh-install.sh -a
```
Installs Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard.

Verification:
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

**Issue — Dashboard stopped loading after instance restart**
- **Root cause:** Public IP address changed on instance restart
- **Fix:** Update the Wazuh Manager IP in the Windows Agent's `ossec.conf`, restart the agent, and confirm the AWS Security Group allows SSH and HTTPS

### Phase 4: Wazuh Agent Installation
- Install the Windows Agent package
- Configure the manager address to the Wazuh public IP
- Register and restart the agent

Verification:
```powershell
Get-Service Wazuh*
```
Agent should appear online in the Wazuh Dashboard.

### Phase 5: Sysmon Deployment
- Install Sysmon64 with the Olaf Hartong configuration:
```powershell
sysmon64.exe -i sysmonconfig.xml
```
- Verify events locally:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```

**Issue — Sysmon logs visible locally but not appearing in Wazuh**
- **Root cause:** Default `ossec.conf` only collected Application, Security, and System logs — not `Microsoft-Windows-Sysmon/Operational`
- **Fix:** Add the Sysmon channel to `ossec.conf`, restart the Wazuh Agent, and confirm `ossec.log` shows it analyzing the Sysmon channel

### Phase 6: Wazuh Detection Engineering
Enable log archiving in `/var/ossec/etc/ossec.conf`:
```xml
<logall_json>yes</logall_json>
```
```bash
systemctl restart wazuh-manager
tail -f /var/ossec/logs/archives/archives.json
```

### Phase 7: Custom Detection Rule — Mimikatz
File: `/var/ossec/etc/rules/local_rules.xml`

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz usage detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

| Element | Purpose |
|---|---|
| `if_group: sysmon_event1` | Restricts evaluation to Sysmon Process Creation events |
| `win.eventdata.originalFileName` | Matches the executable's original file name |
| `(?i)mimikatz\.exe` | Case-insensitive match on Mimikatz binary |
| MITRE mapping | T1003 — Credential Dumping |

Restart the manager and execute `mimikatz.exe` to confirm the alert (**Rule ID 100002, Level 15**) fires in the Wazuh Alerts Index.

### Phase 8: Wazuh → Shuffle SOAR Integration
Add a Shuffle integration block to `/var/ossec/etc/ossec.conf` targeting the Shuffle webhook URL, scoped to `rule_id: 100002`, sending JSON-formatted alerts.

```
Wazuh Alert Generated
      ↓
Wazuh sends JSON
      ↓
Shuffle Webhook receives event
      ↓
New workflow execution appears under Explore → Runs
```

### Phase 9: Shuffle Workflow Design
```
Webhook → Regex Extraction → VirusTotal → TheHive → Email Notification
```

- **Webhook Node:** Receives the Wazuh alert JSON (rule ID, agent name, hostname, event data, hashes, timestamp)
- **Regex Node:** Extracts the SHA256 hash from the Sysmon event using `SHA256=([A-Fa-f0-9]{64})`
- **VirusTotal Node:** Runs a Get Hash Report lookup on the extracted SHA256 for threat enrichment

### Phase 10: TheHive Integration
- Created organization `Irfan-SOC-Automation` with an analyst user and a dedicated service account
- Generated and securely stored an API key for the service account

**Troubleshooting**

| Issue | Cause | Resolution |
|---|---|---|
| `401 Authentication Failure` | Authorization header misconfigured | Use `Authorization: Bearer API_KEY` |
| `400 Invalid JSON` | Shuffle HTTP node generated malformed JSON | Validate JSON structure before sending |
| `error.expected.jsstring` at `.sourceRef` | `sourceRef` passed as a numeric value (`"sourceRef":100002`) | Cast to string (`"sourceRef":"100002"`) |
| `Alert already exists` | `source` + `sourceRef` form TheHive's uniqueness key, and every alert reused the static rule ID | Use a unique value per alert, e.g. the Wazuh Alert ID (`"sourceRef":"1781859310.1424611"`) |

**Final result:** `HTTP 201 Created` — alert successfully created in TheHive.

```
Webhook     → Success
Regex       → Success
VirusTotal  → Success
TheHive     → Success
Email       → Ready
```

## Lessons Learned
1. Sysmon installed correctly does not guarantee Wazuh collection
2. The Wazuh Agent must explicitly monitor the Sysmon channel
3. Discover index selection matters
4. Public IP changes after an AWS instance stop/start can break connectivity
5. Security Groups are frequently responsible for SSH failures
6. Wazuh archives are critical when troubleshooting telemetry ingestion
7. Custom rules require exact field names
8. Sysmon Event ID 1 is ideal for process creation detection

## Skills Demonstrated
- SOC pipeline design and deployment
- SIEM administration (Wazuh)
- Detection engineering (custom Sysmon-based rules)
- SOAR workflow automation (Shuffle)
- Threat intelligence enrichment (VirusTotal)
- Incident/case management (TheHive)
- REST API troubleshooting and authentication
- AWS cloud infrastructure management

## MITRE ATT&CK Mapping
| Technique | ATT&CK ID |
|---|---|
| Credential Dumping (Mimikatz) | T1003 |

## Technologies Used
Wazuh Manager / Indexer / Dashboard, Wazuh Agent, Sysmon (Olaf Hartong config), Shuffle SOAR, VirusTotal API, TheHive, AWS EC2, Windows 11

## Disclaimer
This project was built in a controlled lab environment for educational and defensive cybersecurity purposes only. All testing was performed on systems owned or authorized for testing. No unauthorized systems or networks were targeted.

## Support the Project
If you found this project helpful, consider giving it a ⭐ Star. Contributions, suggestions, and feedback are always welcome!
