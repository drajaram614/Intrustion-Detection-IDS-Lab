# Intrusion Detection Lab with Suricata and Wazuh Integration

## Overview

This lab focuses on implementing **Suricata**, a high-performance network threat detection engine, alongside **Wazuh** for improved logging and monitoring. Suricata, operating as an Intrusion Detection System (IDS), scans network traffic in real-time to detect suspicious activities, while Wazuh acts as a Security Information and Event Management (SIEM) tool to analyze and visualize logs. This setup enhances the security of a network environment by integrating IDS and SIEM functionalities across multiple Virtual Machines (VMs) for comprehensive network and system monitoring.

## Why This Lab is Important

By combining IDS/IPS capabilities (Suricata) with SIEM logging and analysis (Wazuh), this lab introduces essential cybersecurity concepts like threat detection, network traffic analysis, and incident response. Understanding how to set up and configure these tools is valuable for any security professional as it builds proficiency in:

- Detecting network anomalies and potential attacks
- Gaining visibility into network traffic patterns
- Correlating IDS alerts with a SIEM for actionable insights

This lab demonstrates how to configure and deploy IDS/IPS systems and leverage SIEM integration for holistic threat visibility, improving the security and resilience of network environments.

---

## Lab Walkthrough

### 1. Setting Up Suricata

**Suricata** is deployed as an IDS to monitor and detect threats by analyzing network traffic.

- **Verify Suricata Installation**: Start by checking Suricata's status to confirm that it is active.

    ```bash
    sudo systemctl status suricata
    ```

    ![Suricata Active Status](path/to/image.png)

- **Confirm Suricata Configuration Files**: Navigate to `/etc/suricata` to see the Suricata configuration files, which include `suricata.yaml` (the main config file) and the rules folder.

    ```bash
    ls -al /etc/suricata
    ```

    ![Suricata Config Files](path/to/image.png)

    ```bash
    ls -al /etc/suricata/rules
    ```

    ![Suricata Rules Folder](path/to/image.png)

- **Identify Network Interface**: Use `ifconfig` or `ip a s` to identify your network interface details (IP, subnet, etc.). This information is essential for configuring Suricata’s network settings.

    ```bash
    ifconfig
    ```

    ![Network Interface Info](path/to/image.png)

    ```bash
    ip a s
    ```

    ![IP Address and Range](path/to/image.png)

### 2. Configuring Suricata

- **Edit the Suricata Configuration File**: Modify `suricata.yaml` to specify network ranges and address groups to match your environment.

    ![Suricata Address Group Config](path/to/image.png)

- **Specify Network Interface for Packet Capture**: Under the `af-packet` section, define the network interface Suricata should monitor.

    ![Suricata AF-Packet Config](path/to/image.png)

- **Enable Flow IDs for Event Correlation**: Set `community-flow-id` to enable log import in JSON format, which allows better integration with tools like Zeek and Wazuh for event correlation.

    ![Enable Flow ID in Suricata](path/to/image.png)

- **Load Configuration and Rules**: After editing, update Suricata’s configuration and load the rules.

    ```bash
    sudo suricata -T -c /etc/suricata/suricata.yaml
    ```

    ![Config and Rules Loaded](path/to/image.png)

### 3. Checking Log Files

- **Verify Log Output**: Suricata logs are located at `/var/log/suricata`. Check the folder to ensure logs like `eve.json`, `fast.log`, and `stats.log` are populated.

    ```bash
    ls -al /var/log/suricata
    ```

    ![Suricata Log Files](path/to/image.png)

---

### 4. Testing Suricata Detection Capabilities

1. **Generate Test Traffic**: Use the `curl` command to simulate a request to `testmynids.org` and check Suricata’s response in `fast.log`.

    ```bash
    curl http://testmynids.org/uid/index.html
    sudo cat /var/log/suricata/fast.log
    ```

    ![Suricata Detection Test](path/to/image.png)

2. **Add Custom Rules**: Create a custom rule for ICMP pings to detect if any external VM pings your system. Add this rule in `local.rules`:

    ```plaintext
    alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; sid:1; rev:1;)
    ```

    Modify `suricata.yaml` to include the path to custom rules, then test with:

    ```bash
    sudo suricata -T -c /etc/suricata/suricata.yaml -v
    ```

    ![Custom Rule Testing](path/to/image.png)

3. **Simulate ICMP Attack**: From a different VM, ping the IP running Suricata. Check `fast.log` to verify Suricata flagged the ICMP pings.

    ```bash
    ping [Suricata_VM_IP]
    ```

    ![Fast Log - ICMP Detection](path/to/image.png)

---

### 5. Integrating with Wazuh

**Wazuh** is configured to monitor logs from Suricata, acting as a centralized SIEM solution to visualize and analyze security events.

1. **Install Wazuh**: Start by setting up Wazuh and confirm all services are running. 

    ![Wazuh Installation](path/to/image.png)

2. **Add Suricata Logs to Wazuh**: Configure the Wazuh agent on the Suricata VM to send `eve.json` logs to Wazuh. Validate that the Suricata VM IP is correctly added in the Wazuh config file.

    ![Wazuh Config File](path/to/image.png)

3. **Confirm Wazuh Dashboard Connectivity**: Access the Wazuh dashboard and check for the Suricata agent’s connection. You should see live logs from `eve.json`.

    ![Wazuh Dashboard - Suricata Logs](path/to/image.png)

4. **Visualize ICMP Ping Events**: Verify that Wazuh displays detailed information about the ICMP ping tests performed earlier, providing insights into alert severity and source.

    ![Wazuh ICMP Event Details](path/to/image.png)

---

## Skills and Knowledge Gained

- **Network Traffic Analysis**: Monitoring and analyzing network traffic, understanding protocols, and identifying anomalies.
- **Threat Detection and Prevention**: Hands-on experience configuring rules to detect network threats.
- **IDS/IPS Deployment**: Practical knowledge in setting up and managing IDS/IPS tools for real-world scenarios.
- **Security Automation and Troubleshooting**: Enhanced skills in troubleshooting IDS/IPS setups, automating alerts, and integrating SIEM solutions.

This lab equips you with a foundational understanding of IDS and SIEM tools, preparing you to deploy similar configurations in enterprise environments. By mastering these tools, you can ensure better network security, early threat detection, and efficient response strategies.