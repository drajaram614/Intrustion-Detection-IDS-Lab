# Intrusion Detection & Security Operations Lab
## Suricata IDS with Wazuh SIEM Integration & Active Threat Simulation

<p align="center">
    <img src="images/title.png" alt="Main Image" />
</p>

---

## Executive Summary

This comprehensive security operations lab demonstrates the implementation of an enterprise-grade **Intrusion Detection System (IDS)** using **Suricata**, integrated with **Wazuh** as a **Security Information and Event Management (SIEM)** platform. The lab extends beyond basic IDS/IPS deployment to include **active threat simulation**, **real-time alert generation**, and **incident response workflows** that mirror real-world Security Operations Center (SOC) environments.

By combining Suricata's network-level threat detection with Wazuh's log aggregation, visualization, and alerting capabilities, this lab establishes a **defense-in-depth** monitoring strategy. The integration enables security analysts to detect, investigate, and respond to threats across multiple attack vectors—from network reconnaissance to privilege escalation and persistence mechanisms.

The lab culminates in a **live attack simulation** where I executed common attacker techniques (credential abuse, privilege escalation, service creation, persistence mechanisms, and log tampering) and successfully detected each through Wazuh's alerting framework. This demonstrates the practical application of **threat detection**, **incident response**, and **security monitoring** in a controlled environment.

---

## Why This Lab Matters

### The Cybersecurity Skills Gap

Organizations face a critical shortage of cybersecurity professionals who understand both the **technical implementation** and **operational use** of security tools. This lab bridges that gap by providing hands-on experience with:

- **Network Traffic Analysis**: Understanding protocols, identifying anomalies, and detecting malicious patterns
- **Threat Detection and Prevention**: Configuring detection rules and understanding attack signatures
- **SIEM Deployment and Management**: Centralizing logs, creating dashboards, and generating actionable alerts
- **Incident Response Workflows**: From detection to investigation and remediation
- **Security Automation**: Implementing automated alerting and response mechanisms
- **MITRE ATT&CK Framework Mapping**: Understanding attacker techniques and tactics in context

### Real-World Application

In enterprise environments, security teams must monitor both **network traffic** (via IDS/IPS like Suricata) and **system logs** (via SIEMs like Wazuh). The integration demonstrated in this lab reflects actual SOC architectures where:

- **Suricata** monitors network traffic for known attack signatures and anomalies
- **Wazuh** collects logs from endpoints, applications, and security tools
- **Alert correlation** identifies sophisticated attacks that might otherwise go undetected
- **Centralized dashboards** enable rapid threat hunting and incident investigation

### How This Lab Prepares Me for the SOC

| Skill Developed | Application in Enterprise SOC |
|-----------------|-------------------------------|
| IDS/IPS Configuration | Deploying and tuning detection systems |
| Log Analysis | Investigating security events |
| Threat Detection | Identifying malicious activity |
| Incident Response | Following escalation procedures |
| Tool Integration | Building comprehensive monitoring stacks |
| Attack Simulation | Understanding attacker methodology |

---

## Lab Architecture

### Component Overview

<p align="center">
    <img src="images/title.png" alt="Lab Architecture" />
</p>

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Network IDS** | Packet inspection and threat detection | Suricata |
| **SIEM Platform** | Log aggregation, correlation, and visualization | Wazuh |
| **Endpoint Agent** | System log collection and monitoring | Wazuh Agent |
| **Attack Platform** | Threat simulation and testing | WSL2 Ubuntu |
| **Target Endpoint** | Monitored system generating logs | Windows 11 |

### How the Components Work Together

1. **Suricata** monitors network traffic passing through the host system, analyzing packets for known attack signatures and suspicious patterns
2. **Wazuh** collects logs from the Windows endpoint (Security, System, Application logs) as well as Suricata's `eve.json` output
3. **Wazuh Dashboard** provides real-time visualization, alerting, and search capabilities
4. **Attack simulations** generate traffic and system events that trigger Suricata and Wazuh alerts
5. **MITRE ATT&CK mapping** contextualizes alerts within the framework of adversary tactics and techniques

---

## Part 1: Suricata IDS Implementation

### What is Suricata?

Suricata is a high-performance **Network Intrusion Detection System (NIDS)** that operates by inspecting network traffic in real-time. It analyzes packets against a comprehensive ruleset to identify known attack patterns, suspicious behaviors, and policy violations.

**Key Capabilities:**
- **Protocol Analysis**: Deep inspection of HTTP, TLS, DNS, and other protocols
- **File Extraction**: Extracting files from network traffic for analysis
- **TLS Fingerprinting**: Identifying encrypted traffic patterns
- **Performance**: Multi-threaded architecture for high-throughput environments

### Installation and Setup

#### Verify Suricata Installation

```bash
sudo systemctl status suricata
```

<p align="center">
    <img src="images/image4.png" alt="Suricata Active Status" />
</p>

#### Examine Configuration Files

Suricata's primary configuration is stored in `/etc/suricata/suricata.yaml`. This file controls:
- Network interface selection
- Home network definitions
- Rule paths
- Logging configurations

```bash
ls -al /etc/suricata
ls -al /etc/suricata/rules
```

<p align="center">
    <img src="images/image21.png" alt="Suricata Config Files" />
    <img src="images/image24.png" alt="Suricata Rules Folder" />
</p>

#### Network Interface Configuration

Identifying the network interface is critical for Suricata to capture traffic on the correct interface.

```bash
ifconfig
```

<p align="center">
    <img src="images/image13.png" alt="Network Interface Info" />
</p>

```bash
ip a s
```

<p align="center">
    <img src="images/image26.png" alt="IP Address and Range" />
</p>

### Suricata Configuration

#### Network Range Definition

I configured Suricata to monitor my specific network by defining address groups in `suricata.yaml`:

<p align="center">
    <img src="images/image10.png" alt="Suricata Address Group Config" />
</p>

#### Packet Capture Configuration

The `af-packet` section defines which interface Suricata should monitor for packet capture:

<p align="center">
    <img src="images/image15.png" alt="Suricata AF-Packet Config" />
</p>

#### Enabling Flow IDs for Event Correlation

I enabled `community-flow-id` to ensure logs are in JSON format, enabling integration with Wazuh and other SIEM tools:

<p align="center">
    <img src="images/image22.png" alt="Enable Flow ID in Suricata" />
</p>

#### Loading Configuration and Rules

After editing the configuration, I validated it and loaded the rules:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

<p align="center">
    <img src="images/image1.png" alt="Config and Rules Loaded" />
    <img src="images/image9.png" alt="Config and Rules Loaded" />
</p>

### Enhancing Detection with Additional Sources

I integrated multiple threat intelligence sources to broaden Suricata's detection capabilities:

| Source | Purpose |
|--------|---------|
| **ET/Open** | Community-driven ruleset for emerging threats |
| **tgreen/hunting** | Advanced detection rules for proactive threat hunting |
| **malsilo/win-malware** | Specialized Windows malware detection |

This integration strengthens Suricata's ability to detect complex threats across different attack vectors, improving overall network defense.

<p align="center">
    <img src="images/image7.png" alt="Adding sources to suricata" />
</p>

### Log File Verification

After configuration, I verified that Suricata was generating logs in `/var/log/suricata/`:

```bash
ls -al /var/log/suricata
```

<p align="center">
    <img src="images/image18.png" alt="Suricata Log Files" />
</p>

**Key Log Files:**
- `eve.json`: JSON-format event logs (used for SIEM integration)
- `fast.log`: Brief alert format for quick review
- `stats.log`: Performance statistics

### Testing Suricata Detection Capabilities

#### Generate Test Traffic

To verify Suricata was working, I generated test traffic using `curl`:

```bash
curl http://testmynids.org/uid/index.html
sudo cat /var/log/suricata/fast.log
```

<p align="center">
    <img src="images/image6.png" alt="Suricata Detection Test" />
</p>

#### Create Custom Rules

I created a custom rule to detect ICMP pings and test rule creation:

**Rule File: `local.rules`**
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; sid:1; rev:1;)
```

<p align="center">
    <img src="images/image12.png" alt="Custom Rule" />
</p>

After adding the rule, I updated Suricata's configuration to include `local.rules`:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

<p align="center">
    <img src="images/image16.png" alt="Custom Rule Testing" />
</p>

#### Simulate ICMP Attack

From another VM, I pinged the Suricata VM to generate alerts:

```bash
ping [Suricata_VM_IP]
```

<p align="center">
    <img src="images/image14.png" alt="pinging vm" />
</p>

Suricata successfully detected the ICMP traffic and logged the alert in `fast.log`:

<p align="center">
    <img src="images/image5.png" alt="Fast Log - ICMP Detection" />
</p>

---

## Part 2: Wazuh SIEM Implementation

### What is Wazuh?

Wazuh is an open-source **Security Information and Event Management (SIEM)** platform that provides:

- **Log Collection and Analysis**: Aggregating logs from multiple sources
- **Threat Detection**: Correlation and alerting based on rules
- **Vulnerability Detection**: Identifying missing patches and vulnerabilities
- **File Integrity Monitoring**: Tracking changes to critical system files
- **Security Configuration Assessment**: Evaluating compliance with security standards
- **Incident Response**: Tools for investigating and responding to alerts

### Wazuh Architecture

The Wazuh stack consists of three core components:

| Component | Function |
|-----------|----------|
| **Wazuh Manager** | Core engine that processes data, generates alerts, and manages agents |
| **Wazuh Indexer** | Stores indexed logs for fast retrieval (based on OpenSearch) |
| **Wazuh Dashboard** | User interface for visualization, searches, and alert management |

<p align="center">
    <img src="images/image23.png" alt="Wazuh Installation" />
</p>

#### Validate Wazuh Services

**Wazuh Manager:**

```bash
sudo systemctl status wazuh-manager
```

<p align="center">
    <img src="images/image27.png" alt="Wazuh Manager Running" />
</p>

**Wazuh Indexer:**

```bash
sudo systemctl status wazuh-indexer
```

<p align="center">
    <img src="images/image20.png" alt="Wazuh Indexer Running" />
</p>

**Wazuh Dashboard:**

```bash
sudo systemctl status wazuh-dashboard
```

<p align="center">
    <img src="images/image25.png" alt="Wazuh Dashboard Running" />
</p>

### Integrating Suricata with Wazuh

The integration of Suricata and Wazuh provides **centralized monitoring** and **enhanced threat intelligence**, making it easier to detect and respond to potential intrusions.

#### Wazuh Agent Configuration

I configured the Wazuh agent on the Suricata VM to monitor the `eve.json` log file:

<p align="center">
    <img src="images/image3.png" alt="Wazuh Config File" />
    <img src="images/image30.png" alt="Wazuh Config File" />
</p>

**Key Configuration Elements:**
- Agent name and IP address
- Log file path (`/var/log/suricata/eve.json`)
- Log format (JSON)
- Command to read the file

#### Validate Agent Connection

I confirmed the Wazuh agent was installed and actively sending data from the Suricata VM:

<p align="center">
    <img src="images/image17.png" alt="Wazuh Agent Validation" />
    <img src="images/image28.png" alt="Wazuh Agent Validation" />
</p>

#### Dashboard Verification

In the Wazuh Dashboard, I confirmed that Suricata logs were streaming into Wazuh:

<p align="center">
    <img src="images/image19.png" alt="Wazuh Dashboard - Suricata Logs" />
    <img src="images/image2.png" alt="Wazuh Dashboard - Suricata Logs" />
</p>

#### Visualize ICMP Events

The ICMP ping test was visible in the Wazuh dashboard with detailed event information:

<p align="center">
    <img src="images/image29.png" alt="Wazuh ICMP Event Details" />
    <img src="images/image8.png" alt="Wazuh ICMP Event Details" />
    <img src="images/image11.png" alt="Wazuh ICMP Event Details" />
</p>

---

## Part 3: Advanced Threat Simulation and Detection

### Lab Environment

| Component | IP Address | Purpose |
|-----------|------------|---------|
| **Wazuh VM** | 192.168.1.194 | SIEM Server (Manager, Indexer, Dashboard) |
| **Windows Host** | 192.168.1.241 (10.255.255.254 from WSL2) | Monitored Endpoint with Wazuh Agent |
| **Ubuntu WSL2** | N/A | Attack Platform (nmap, hydra, etc.) |
| **Suricata VM** | N/A | Network IDS |

### Enabling Windows Auditing

Before generating security events, I enabled Windows auditing for critical security events. This mirrors the **log source configuration** phase in enterprise SOC environments where analysts ensure proper logging is enabled before monitoring.

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /get /category:"Account Management"
```

<p align="center">
    <img src="images/auditpol.png" alt="Enabling Windows Auditing" />
</p>

**What This Does:**
- Enables auditing for user account changes (EventID 4720)
- Enables auditing for group membership changes (EventID 4732)
- Enables auditing for logon events (EventID 4624, 4625)
- Enables auditing for process creation (EventID 4688)

**SOC Context:** Auditing is the foundation of security monitoring. Without proper auditing, attackers can operate undetected. This step ensures the Windows host generates the necessary logs for effective threat detection.

---

### Attack 1: User Account Creation (EventID 4720)

#### Attack Execution

**Command:**
```powershell
net user attacker P@ssw0rd123 /add
```

**PowerShell Screenshot:**

```
PS C:\Program Files (x86)\ossec-agent> net user attacker P@ssw0rd123 /add
The command completed successfully.
```

#### What This Does

In a real attack scenario, this command creates a new user account on the Windows system. Attackers use this technique to:

- **Establish Persistence**: Create a backdoor account that remains active even after the initial compromise
- **Maintain Access**: Ensure continued access to the compromised system
- **Hide Malicious Activity**: Use the account for lateral movement without using compromised credentials

#### The Bigger Picture

Creating a new user account is a critical phase in an attack lifecycle:

| Phase | Attacker Goal | Indicator |
|-------|---------------|-----------|
| Initial Access | Gain entry to the system | Suspicious process execution |
| Persistence | Maintain access | New account creation |
| Privilege Escalation | Increase access level | Account added to privileged groups |
| Lateral Movement | Move across the network | Reuse of created account |

#### Wazuh Detection

**Alert: User account enabled or created (Level 8)**

```
timestamp: Jun 18, 2026 @ 13:20:10.963
agent.name: DESKTOP-3QDQSU0
rule.mitre.id: T1098
rule.mitre.tactic: Persistence
rule.description: User account enabled or created
rule.level: 8
```

<p align="center">
    <img src="images/user_created.png" alt="Wazuh Alert - User Account Created" />
</p>

#### Understanding the Alert

| Field | Value | Interpretation |
|-------|-------|----------------|
| Event ID | 4720 | Windows event indicating user account creation |
| Severity | Level 8 | High-medium severity |
| MITRE ATT&CK | T1098 | Account Manipulation - Persistence technique |
| Detection | Created user "attacker" | Alert triggered by account creation |

**Why This Matters:** New user account creation is a common indicator of compromise. In enterprise environments, security teams monitor EventID 4720 to detect potential backdoor accounts. The account name "attacker" is clearly suspicious and would trigger immediate investigation.

---

### Attack 2: Privilege Escalation - Administrators Group (EventID 4732)

#### Attack Execution

**Command:**
```powershell
net localgroup administrators attacker /add
```

**PowerShell Screenshot:**

```
PS C:\Program Files (x86)\ossec-agent> net localgroup administrators attacker /add
The command completed successfully.
```

#### What This Does

This command adds the newly created user to the **Administrators group**, giving it full system privileges. In real attacks, this is a critical **privilege escalation** step where attackers elevate their access to system-level control.

#### The Bigger Picture

Adding a user to the Administrators group enables:

| Attack Impact | Description |
|---------------|-------------|
| **Full System Control** | Install software, modify configuration, access all files |
| **Persistence** | Create scheduled tasks, services, and backdoors |
| **Credential Access** | Dump password hashes from SAM registry |
| **Lateral Movement** | Use admin credentials to access other systems in the network |

#### Attack Chain

```
Initial Access (User Creation) → Privilege Escalation (Admin Group) → 
Persistence (Services/Tasks) → Credential Access (SAM Dump) → 
Lateral Movement (Other Systems)
```

#### Wazuh Detection

**Alert: Administrators Group Changed (Level 12 - HIGH SEVERITY)**

```
timestamp: Jun 18, 2026 @ 13:20:14.534
agent.name: DESKTOP-3QDQSU0
rule.mitre.id: T1484
rule.mitre.tactic: Defense Evasion, Privilege Escalation
rule.description: Administrators Group Changed
rule.level: 12
```

<p align="center">
    <img src="images/admin_changed.png" alt="Wazuh Alert - Administrators Group Changed" />
</p>

#### Alert Details

```json
{
  "data.win.eventdata.targetUserName": "Administrators",
  "data.win.eventdata.memberSid": "S-1-5-21-2328089366-3897637488-1109289522-1010",
  "data.win.eventdata.subjectUserName": "danie",
  "data.win.system.eventID": 4732
}
```

| Field | Value | Interpretation |
|-------|-------|----------------|
| Event ID | 4732 | Member added to security-enabled local group |
| Target Group | Administrators | The group modified |
| SID | S-1-5-21-...-1010 | The new user added to Administrators |
| User | danie | The user who performed the action |
| MITRE ATT&CK | T1484 | Domain Policy Modification |
| **Severity** | **Level 12** | **HIGH SEVERITY - Critical alert** |

**Why This is Critical (Level 12):** Adding any user to the Administrators group is a severe security event. In a real SOC, this would generate a high-priority ticket requiring immediate investigation. The combination of (1) new user creation + (2) admin group addition = clear evidence of a successful privilege escalation attack.

**SOC Response Would Include:**
1. **Immediate investigation**: Who created the user? Why?
2. **User verification**: Was this authorized?
3. **System isolation**: Temporarily isolate the compromised endpoint
4. **Remediation**: Remove the unauthorized user and admin access
5. **Root cause analysis**: How did the attacker gain initial access?

---

### Attack 3: Service Creation (EventID 7045)

#### Attack Execution

**Command:**
```powershell
sc.exe create "TestService" binPath= "C:\Windows\System32\cmd.exe" start= auto
```

**PowerShell Screenshot:**

```
PS C:\Program Files (x86)\ossec-agent> sc.exe create "TestService" binPath= "C:\Windows\System32\cmd.exe" start= auto
[SC] CreateService SUCCESS
```

#### What This Does

This command creates a new Windows service that runs `cmd.exe` automatically at system startup. Attackers use service creation for:

- **Persistence**: Services restart automatically if stopped or crashed
- **Privilege Escalation**: Services often run with SYSTEM privileges
- **Evasion**: Legitimate-looking service names can hide malicious activity
- **Command Execution**: Services can run arbitrary commands

#### The Bigger Picture

Services are one of the most common persistence mechanisms used by attackers:

| Service Type | Purpose | Example |
|--------------|---------|---------|
| **Backdoor Service** | Maintain access | Connects to C2 server |
| **Payload Service** | Execute malware | Runs ransomware |
| **Lateral Movement Tool** | Spread to other systems | Drops malware on network |
| **Credential Access Tool** | Dump credentials | Mimikatz service |

#### MITRE ATT&CK Mapping

**T1543.003 - Create or Modify System Process: Windows Service**

| Attack Phase | Description | Why Attackers Use Services |
|--------------|-------------|----------------------------|
| Persistence | Establish foothold | Services restart automatically |
| Privilege Escalation | Increase privileges | Services run with SYSTEM rights |
| Defense Evasion | Hide activity | Services look like legitimate software |

#### Wazuh Detection

**Alert: New Windows Service Created (Level 5)**

```
timestamp: Jun 18, 2026 @ 13:20:17.581
agent.name: DESKTOP-3QDQSU0
rule.mitre.id: T1543.003
rule.mitre.tactic: Persistence, Privilege Escalation
rule.description: New Windows Service Created
rule.level: 5
```

<p align="center">
    <img src="images/service_created.png" alt="Wazuh Alert - Service Created" />
</p>

#### Alert Details

| Field | Value | Interpretation |
|-------|-------|----------------|
| Event ID | 7045 | New service was created |
| Service Name | TestService | Suspicious service name |
| Binary Path | C:\Windows\System32\cmd.exe | Just runs command prompt |
| MITRE ATT&CK | T1543.003 | Windows Service creation |

**Why This Matters:** While Level 5 is moderate severity, the combination of a suspicious service name ("TestService") and an executable path (`cmd.exe`) would raise red flags in a real SOC. Services are often used as persistence mechanisms, and this alert would trigger investigation into:
- Who created the service?
- What is the purpose of the service?
- Does the service communicate with external IPs?
- Are there other persistence mechanisms present?

---

### Attack 4: Scheduled Task Creation (EventID 4698)

#### Attack Execution

**Command:**
```powershell
schtasks /create /tn "TestTask" /tr "cmd.exe" /sc minute /mo 5
```

**PowerShell Screenshot:**

```
PS C:\Program Files (x86)\ossec-agent> schtasks /create /tn "TestTask" /tr "cmd.exe" /sc minute /mo 5
SUCCESS: The scheduled task "TestTask" has successfully been created.
```

#### What This Does

This command creates a scheduled task that runs `cmd.exe` every 5 minutes. Attackers use scheduled tasks for:

- **Persistence**: Tasks run automatically on schedule
- **Privilege Escalation**: Tasks can run with SYSTEM privileges
- **Lateral Movement**: Tasks can execute commands on other systems
- **Command Execution**: Run arbitrary code at scheduled intervals

#### The Bigger Picture

Scheduled tasks are another critical persistence mechanism:

| Use Case | Description | Real-World Example |
|----------|-------------|-------------------|
| **Legitimate Use** | System maintenance, backups, updates | Windows Update tasks |
| **Malicious Use** | Malware execution, command-and-control | APT groups use scheduled tasks |

**How Attackers Use Scheduled Tasks:**

1. **Initial Persistence**: Create task to run malware every 5 minutes
2. **Reconnaissance**: Schedule task to scan network every hour
3. **Lateral Movement**: Use task to run commands on other systems
4. **Exfiltration**: Schedule task to upload stolen data every night
5. **Cleanup**: Schedule task to delete logs and remove evidence

#### MITRE ATT&CK Mapping

**T1053.005 - Scheduled Task**

| Attack Phase | Description | Why Attackers Use Scheduled Tasks |
|--------------|-------------|-----------------------------------|
| Execution | Run malicious code | Tasks execute commands on schedule |
| Persistence | Maintain access | Tasks continue after reboots |
| Lateral Movement | Move across network | Tasks can run remote commands |
| Command and Control | Maintain communication | Tasks can call out to C2 servers |

#### Wazuh Detection

**Alert: Scheduled Task Created (Level 5)**

```
timestamp: Jun 18, 2026 @ 13:20:17.581 (from service creation)
```

<p align="center">
    <img src="images/task_created.png" alt="Wazuh Alert - Scheduled Task Created" />
</p>

#### Alert Details

| Field | Value | Interpretation |
|-------|-------|----------------|
| Event ID | 4698 | Scheduled task was created |
| Task Name | TestTask | Suspicious name |
| Command | cmd.exe | Just runs command prompt |
| Schedule | Every 5 minutes | Very frequent execution |

**Why This Matters:** While a scheduled task running `cmd.exe` might seem innocuous, the combination of:
1. Suspicious task name ("TestTask")
2. Very short interval (5 minutes)
3. Running an interactive shell (`cmd.exe`)

Would trigger a full investigation in a real SOC. Attackers often use scheduled tasks to:
- Maintain persistence after system reboots
- Run reconnaissance tools regularly
- Exfiltrate data slowly over time
- Ensure malware continues running even if stopped

---

### Attack 5: Log Tampering (EventID 1102)

#### Attack Execution

**Command:**
```powershell
wevtutil cl Security
```

**PowerShell Screenshot:**

```
PS C:\Program Files (x86)\ossec-agent> wevtutil cl Security
PS C:\Program Files (x86)\ossec-agent>
```

#### What This Does

This command clears the Windows Security log, removing all evidence of activity. Attackers use log clearing to:

- **Evade Detection**: Remove evidence of malicious activity
- **Destroy Forensic Evidence**: Make investigation impossible
- **Hide Attack Chain**: Remove logs that show initial access
- **Impede Incident Response**: Make it harder to determine what happened

#### The Bigger Picture

Log tampering is a critical **defense evasion** technique:

| Attack Impact | Description |
|---------------|-------------|
| **Timeline Loss** | Cannot determine when attack started |
| **Evidence Destruction** | Cannot identify how attacker gained access |
| **Root Cause Loss** | Cannot determine what was accessed/stolen |
| **Response Impediment** | Cannot properly investigate the incident |

**Why Attackers Clear Logs:**

1. **Cover Their Tracks**: Remove evidence of initial compromise
2. **Slow Investigation**: Make it harder for security teams
3. **Hide Lateral Movement**: Remove evidence of moving to other systems
4. **Conceal Data Exfiltration**: Remove evidence of data theft

#### Wazuh Detection

**Alert: A Windows log file was cleared (Level 5)**

```
timestamp: Jun 18, 2026 @ 13:46:54.652
agent.name: DESKTOP-3QDQSU0
rule.mitre.id: T1070
rule.mitre.tactic: Defense Evasion
rule.description: A Windows log file was cleared
rule.level: 5
```

<p align="center">
    <img src="images/log_cleared.png" alt="Wazuh Alert - Log Clearing" />
</p>

#### Alert Details

| Field | Value | Interpretation |
|-------|-------|----------------|
| Event ID | 1102 | Windows security log was cleared |
| MITRE ATT&CK | T1070 | Indicator Removal on Host |
| MITRE Tactic | Defense Evasion | Attackers hiding activity |
| Multiple Alerts | 4+ instances | Defender/Windows Defender also triggered |

**Why This Matters:** Log clearing is one of the most critical indicators of a sophisticated attack. When attackers clear logs, it indicates they are:
1. **Experienced**: They know about security logs
2. **Prepared**: They have taken steps to avoid detection
3. **Advanced**: They are covering their tracks thoroughly

**In a real SOC:** An alert for EventID 1102 would immediately trigger:
1. **Critical incident**: Log clearing is always suspicious
2. **Immediate investigation**: Determine what logs were deleted
3. **Forensic analysis**: Attempt to recover deleted logs
4. **Full compromise assessment**: Assume attacker has root privileges

---

## Understanding Wazuh Rules and Alert Severity

### Rule Severity Levels

| Level | Severity | Description | Example |
|-------|----------|-------------|---------|
| **15** | Critical | Immediate threat requiring action | Ransomware detection, zero-day exploit |
| **12-14** | High | Serious security event requiring investigation | Admin group changes, credential access |
| **8-11** | Medium | Suspicious activity worth investigation | User account creation, privilege changes |
| **5-7** | Low | Minor security events for monitoring | Service creation, scheduled tasks |
| **0-4** | Informational | General system events | Logon events, normal operations |

### Our Alert Breakdown

| Attack | Severity | Level | MITRE Tactic | Significance |
|--------|----------|-------|--------------|--------------|
| Admin Group Changed | HIGH | 12 | Privilege Escalation | Critical escalation |
| User Account Created | Medium | 8 | Persistence | Account manipulation |
| User Account Changed | Medium | 8 | Persistence | Account manipulation |
| Service Created | Low | 5 | Persistence | Service persistence |
| Log Cleared | Low | 5 | Defense Evasion | Evidence tampering |
| Scheduled Task | Low | 5 | Persistence | Persistence mechanism |

---

## Windows Event IDs Reference

| Event ID | Description | Attack Detection |
|----------|-------------|------------------|
| **4624** | Successful logon | Monitor for unusual login times/geographies |
| **4625** | Failed logon | Potential brute force attempts |
| **4648** | Explicit credential logon | Pass-the-hash or credential misuse |
| **4688** | Process creation | Monitor for suspicious process names/arguments |
| **4698** | Scheduled task creation | Potential persistence mechanism |
| **4720** | User account created | Potential backdoor account |
| **4732** | User added to admin group | Privilege escalation |
| **4738** | User account changed | Account manipulation |
| **7045** | New service created | Persistence mechanism |
| **1102** | Security log cleared | Evidence tampering |

---

## How This Lab Mirrors Real SOC Operations

### The SOC Investigation Workflow

```
1. LOG INGESTION
   - Windows Endpoint → Wazuh Agent
   - Suricata → Wazuh Integration
   - Centralized storage in Wazuh Indexer
   
2. ALERT GENERATION
   - Wazuh rules process incoming logs
   - Alerts generated based on rules
   - Severity levels assigned
   - MITRE ATT&CK mapping applied
   
3. ALERT ANALYSIS
   - Analyst reviews dashboard
   - Searches for specific event IDs
   - Investigates alert details
   - Determines severity and response
   
4. INCIDENT RESPONSE
   - Escalate critical alerts
   - Contain affected systems
   - Remove threats
   - Document findings
```

### Our Attack Scenario in the SOC Context

1. **Initial Access**: (Not simulated) - Attacker gains access
2. **Persistence**: User account created (EventID 4720) - Level 8
3. **Privilege Escalation**: Admin group added (EventID 4732) - **Level 12**
4. **Persistence**: Service created (EventID 7045) - Level 5
5. **Persistence**: Scheduled task (EventID 4698) - Level 5
6. **Defense Evasion**: Logs cleared (EventID 1102) - Level 5

**This is a realistic attack chain** that security analysts would investigate in a real SOC.

---

## Incident Response Workflow for This Lab

### When an Alert Triggers

**Phase 1: Detection**
- Alert appears in Wazuh Dashboard
- Security analyst reviews alert
- Identifies severity and potential impact

**Phase 2: Analysis**
- What: User account added to Administrators (Level 12)
- Who: User "danie" added user "attacker"
- When: June 18, 2026 @ 13:20:14
- Where: DESKTOP-3QDQSU0
- Why: Potential privilege escalation

**Phase 3: Investigation**
- Search for related events (4720, 4698, 7045, 1102)
- Determine full attack chain
- Identify affected systems
- Assess data impact

**Phase 4: Response**
- Isolate affected system
- Remove unauthorized accounts
- Remove malicious services/tasks
- Restore logs from backups
- Implement additional monitoring

**Phase 5: Remediation**
- Update detection rules
- Review auditing configuration
- Verify all backdoors removed
- Document incident

**Phase 6: Recovery**
- Restore system to known-good state
- Verify no persistence remains
- Resume normal operations

---

## Skills and Knowledge Gained

### Technical Skills

| Skill | Application |
|-------|-------------|
| IDS Deployment | Installed and configured Suricata |
| SIEM Implementation | Deployed Wazuh stack (Manager, Indexer, Dashboard) |
| Tool Integration | Connected Suricata to Wazuh |
| Log Analysis | Interpreted Windows Event IDs and Suricata alerts |
| Threat Detection | Identified suspicious activity using rules |
| MITRE ATT&CK | Mapped attacks to tactics and techniques |
| Incident Response | Simulated response workflows |
| Security Auditing | Enabled Windows auditing for security events |

### SOC Skills

1. **Log Source Management**: Configuring and validating log sources
2. **Alert Triage**: Prioritizing alerts based on severity
3. **Event Correlation**: Connecting multiple alerts to identify attack chains
4. **Forensic Investigation**: Analyzing event details and timelines
5. **Threat Hunting**: Proactively searching for indicators of compromise
6. **Incident Response**: Following structured response procedures
7. **Documentation**: Recording findings and actions

---

## Conclusion

This Intrusion Detection and Security Operations lab demonstrates the complete lifecycle of security monitoring: from **configuration** and **integration** of security tools, to **active threat simulation** and **detection**, culminating in **incident response workflows**.

### Key Achievements

1. **Suricata IDS Implementation**: Successfully deployed and configured a network intrusion detection system with custom rules and threat intelligence sources

2. **Wazuh SIEM Deployment**: Installed and configured the full Wazuh stack (Manager, Indexer, Dashboard)

3. **Tool Integration**: Established log flow from Suricata to Wazuh and from Windows endpoint to Wazuh

4. **Auditing Configuration**: Enabled Windows security auditing for comprehensive logging

5. **Attack Simulation**: Executed realistic attacker techniques across multiple phases of the attack lifecycle

6. **Alert Generation**: Successfully triggered alerts for each attack, with severity levels ranging from 5 to 12

7. **Threat Understanding**: Demonstrated the ability to understand and interpret security alerts in context

### Enterprise Relevance

The skills demonstrated in this lab directly translate to enterprise security operations:

| Lab Skill | Enterprise Application |
|-----------|----------------------|
| IDS/IPS Configuration | Deploying network monitoring in production |
| SIEM Deployment | Building SOC infrastructure |
| Log Analysis | Investigating security incidents |
| Attack Simulation | Testing detection capabilities |
| Incident Response | Responding
