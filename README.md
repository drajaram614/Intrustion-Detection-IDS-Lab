# Intrusion Detection Lab with Suricata and Wazuh

## Overview

This lab focuses on setting up and configuring **Suricata** as an Intrusion Detection System (IDS) alongside **Wazuh** for enhanced log monitoring and threat analysis. This project integrates multiple Virtual Machines (VMs) to simulate a network environment for monitoring and analyzing network traffic, gaining valuable hands-on experience with IDS/IPS, and security monitoring.

---

### What is Suricata?

**Suricata** is an open-source, high-performance network threat detection engine that functions as an IDS, Intrusion Prevention System (IPS), and Network Security Monitoring (NSM) tool. By analyzing real-time network traffic, Suricata detects patterns and alerts users to suspicious or malicious activity based on predefined rules. Its packet inspection capabilities span multiple protocols such as HTTP, DNS, and TLS, making it an effective tool for identifying threats such as malware and port scans.

### Why Suricata is Important for Cybersecurity

In cybersecurity, Suricata is essential due to its ability to:
- Detect and alert on potentially harmful traffic before it impacts systems.
- Identify and respond to unusual or malicious network patterns.
- Integrate with Security Information and Event Management (SIEM) solutions like Wazuh, enabling streamlined monitoring and alerting.

---

## How Suricata Works as an IDS

In an IDS setup, Suricata passively monitors network traffic, comparing it against a set of rules to detect malicious activity. Suricata’s deep packet inspection can reveal complex attack patterns and detect anomalies, and its flexibility allows for configuration as an inline IPS or a passive IDS, depending on network requirements.

---

## Setting up Suricata

To configure Suricata, follow these steps:

1. **Installation and Status Verification**:
   - Install Suricata on the VM.
   - Ensure it's running properly.
   - **Screenshot**: Take a screenshot of the active Suricata status.

2. **Suricata Directory Structure**:
   - Navigate to `/etc/suricata`.
   - **Screenshot**: Display the directory structure to show the `rules` folder and `suricata.yaml` file.

3. **Network Interface Configuration**:
   - Use `ifconfig` and `ip a s` to identify the correct network interface.
   - Edit the `suricata.yaml` file to set the IP range and interfaces.
   - **Screenshot**: Capture interface settings and IP information.

4. **Configure Address Groups and af-packet**:
   - Configure address groups in the `suricata.yaml` file.
   - Specify the interface in the `af-packet` section.
   - **Screenshot**: Show the modified `suricata.yaml` with updated address groups and interface settings.

5. **Enable Community Flow ID**:
   - Set community flow ID for event correlation.
   - Ensure JSON format for logs, which aids in integration with Wazuh and other tools.

6. **Load Rules and Test Configuration**:
   - After updating the configuration, reload Suricata and load the rules.
   - **Screenshot**: Show the successful configuration load with updated rules.

7. **Verify Log Files**:
   - Check the `/var/log/suricata` folder for essential logs, including `eve.json`, `fast.log`, and `stats.log`.
   - **Screenshot**: Show the populated log directory.

### Testing Suricata

1. **Basic Network Attack Simulation**:
   - Run a simulated attack, e.g., `curl http://testmynids.org/uid/index.html`.
   - **Screenshot**: Capture the output in `fast.log` to verify Suricata’s detection capabilities.

2. **Creating and Testing Custom Rules**:
   - Create a custom ICMP rule:  
     ```plaintext
     alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; sid:1; rev:1;)
     ```
   - Modify the `suricata.yaml` file to allow access to custom rules.
   - Test the custom rule by pinging the Suricata machine from another VM.
   - **Screenshot**: Show the `fast.log` file to confirm ICMP ping detection.

---

## Setting Up Wazuh for Enhanced Log Monitoring

**Wazuh** is a SIEM solution that centralizes logs and provides comprehensive monitoring and alerting capabilities. It enhances security visibility by aggregating Suricata logs and analyzing them for threats.

### Wazuh Installation and Configuration

1. **Install Wazuh Server and Agents**:
   - Complete the Wazuh server installation.
   - Note your admin credentials:  
     **User**: `admin`  
     **Password**: `ZSPxXlxUhHbUkosYch.BA6R5QFQ1gQ*p`
   - **Screenshot**: Take a screenshot of Wazuh services running.

2. **Configure Suricata Integration with Wazuh**:
   - Add the Wazuh server IP to the Suricata configuration on the VM.
   - Validate the connection between Suricata and Wazuh.
   - **Screenshot**: Capture Wazuh dashboard with agent status.

3. **Confirm Log Ingestion**:
   - Confirm Wazuh is ingesting `eve.json` logs from Suricata.
   - **Screenshot**: Display Wazuh dashboard showing logs from Suricata.

4. **Log Analysis in Wazuh Dashboard**:
   - View detailed information about ICMP ping events and other detected activities.
   - **Screenshot**: Capture the Wazuh dashboard showing ICMP ping detection.

---

## Skills Gained and Benefits of the Lab

Through this lab, you will develop key skills in:

1. **Network Traffic Analysis**:
   - Learn to analyze and interpret network traffic across various protocols, enhancing your ability to spot suspicious patterns.

2. **Threat Detection and Prevention**:
   - Gain experience in setting up detection rules and identifying threats in real-time network traffic.

3. **IDS/IPS Management**:
   - Configure, monitor, and manage IDS/IPS systems in a simulated real-world setting, preparing for deployment in diverse environments.

4. **Security Automation and Troubleshooting**:
   - Develop skills in automating responses to security events and troubleshooting network security issues to optimize IDS/IPS performance.

---

## Conclusion

This lab provides hands-on experience with **Suricata** and **Wazuh**, demonstrating the power of using IDS/IPS in a network security context. Integrating these tools offers robust security capabilities, ensuring proactive detection and monitoring of potential threats. By the end of this lab, you’ll have practical skills for deploying, configuring, and managing IDS/IPS systems in cybersecurity environments.
