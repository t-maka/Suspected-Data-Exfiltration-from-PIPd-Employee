# 🔍 Suspected-Data-Exfiltration-from-PIPd-Employee

## Scenario:
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. I was asked to investigate John's activities on his corporate device (lab-vm-mde) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

## 🕒 Timeline Summary and Findings

### 🔹 Step 1: Initial Detection – ZIP File Activity

We searched the **MDE `DeviceFileEvents`** table for any activity involving `.zip` files and observed frequent, routine actions involving file archiving and movement to a `backup folder`.

```kql
DeviceFileEvents
| where DeviceName == "labwill-vm-mde"
| where FileName endswith ".zip"
| order by Timestamp desc
```

![suspicious 7zip activities](https://github.com/user-attachments/assets/d0b4349e-04e7-4a81-b371-88d7dc841849)

---

### 🔹 Step 2: Investigating Archive Creation
We selected one instance where a ZIP file was created and correlated it with process activity 2 minutes before and after the event. A PowerShell script silently installed 7-Zip and used it to archive employee data.

📅 Timestamp: 2025-06-23T04:50:12.6573918Z

```kql
let VMName = "labwill-vm-mde";
let specificTime = datetime(2025-06-23T04:50:12.6573918Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![suspicious 7zip activities_2](https://github.com/user-attachments/assets/11466774-6a50-458a-be52-b955d9c96437)

---

### 🔹 Step 3: Checking for Network Exfiltration
We examined the same time period for any signs of data exfiltration over the network, but found no suspicious activity in the logs.

```kql
let VMName = "labwill-vm-mde";
let specificTime = datetime(2025-06-23T04:50:12.6573918Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
---

### 🔹 Step 4: Checking for USB-Based Exfiltration
We also reviewed USB activity within a 30-minute window around the event. No suspicious USB device usage was detected.

```kql
let specificTime = datetime(2025-06-23T04:50:12.6573918Z);
let VMName = "labwill-vm-mde";
DeviceEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 30m) .. (specificTime + 30m))
| where ActionType == "UsbDriveMounted" or ActionType == "DriveMounted"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ReportId, InitiatingProcessAccountName, AdditionalFields
```
---

### 🛡️ Response
- Immediate Action: Promptly isolated the system after identifying the suspicious archiving activity.
- Communication: Shared findings with the employee’s manager, including details about the PowerShell script creating archives at regular intervals.
- Result: No clear evidence of data exfiltration was found, but proactive measures were taken.

---

### 🧠 MITRE ATT&CK TTP Mapping

| **Tactic**           | **Technique**           | **ID**           | **Comment**                                   |
| -------------------- | ----------------------- | ---------------- | --------------------------------------------- |
| Execution            | PowerShell              | T1059.001        | PowerShell used for silent 7-Zip install      |
| Resource Development | Ingress Tool Transfer   | T1105 (possible) | If 7-Zip was downloaded                       |
| Collection           | Archive via Utility     | T1560.001        | 7-Zip used to archive employee data           |
| Exfiltration         | Exfiltration Over USB   | T1052.001        | Investigated USB exfiltration vector          |
| Defense Evasion      | Masquerading (possible) | T1036            | If activity was hidden under a benign process |

---

### 🔧 Improvement
Goal: Strengthen security posture and improve future threat hunting processes.

### 🛠️ Preventative Measures:
- Application Control: Restrict unauthorized tools like 7-Zip.
- PowerShell Logging: Ensure script block and module logging is enabled.
- DLP Tools: Deploy rules to flag suspicious archiving or bulk file access.

### 🧪 Detection & Hunting Improvements:
- Behavioral Rules: Alert on recurring PowerShell archiving patterns.
- Baselining: Establish norms for ZIP file creation frequency.

---
## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `June 2025`    | `Tinan Makadjibeye`   |
