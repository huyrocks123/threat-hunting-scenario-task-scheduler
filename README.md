# Threat Hunt Report: Unauthorized Scheduled Task Persistence
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-task-scheduler/blob/main/threat-hunting-scenario-unauthorized-task-scheduler-persistence-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

The IT Helpdesk reported that a user workstation was experiencing recurring pop-ups and performance degradation. Preliminary analysis pointed to a suspicious background process. Cybersecurity was asked to investigate possible persistence mechanisms being used by a malicious actor or script on the endpoint. The goal was to identify, analyze, and confirm if an unauthorized scheduled task had been created and was persisting silently in the background.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for the scheduled task creation, execution, and deletion.

---

## Steps Taken

### 1. Verified Scheduled Task Creation/Execution/Deletion in DeviceProcessEvents

Identified that a scheduled task named UpdaterTask was created, executed, and then deleted on device huy by user "huy" using powershell.exe, indicating a potential persistence mechanism followed by cleanup. This sequence suggests deliberate testing or potentially malicious behavior. Task was created at 2025-05-10T23:19:49.4869401Z, executed at 2025-05-10T23:20:04.8675568Z, and deleted at 2025-05-10T23:20:13.8688643Z. 

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "huy"
| where FileName in~ ("schtasks.exe", "powershell.exe")
| where ProcessCommandLine has_any ("create", "schedule", "schtasks", "register-scheduledtask")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

<img width="1417" alt="Screenshot 2025-05-10 at 8 28 53 PM" src="https://github.com/user-attachments/assets/2fd2eb53-12d1-4e4f-8fcb-e06a72d7d94b" />


---

## Chronological Event Timeline 

### 1. Scheduled Task Creation - UpdaterTask

- **Timestamp:** `2025-05-10T23:19:49.4869401Z`
- **Event:** A scheduled task named UpdaterTask was created by user huy using schtasks.exe with the command "schtasks.exe" /create /tn UpdaterTask /tr notepad.exe /sc hourly /f.
- **Action:** Task creation detected.
- **Initiating Process:** powershell.exe

### 2. Scheduled Task Execution - UpdaterTask

- **Timestamp:** `2025-05-10T23:20:04.8675568Z`
- **Event:** The scheduled task UpdaterTask was executed using the command "schtasks.exe" /run /tn UpdaterTask.
- **Action:** Task execution detected.
- **Initiating Process:** powershell.exe

### 3. Scheduled Task Deletion - UpdaterTask

- **Timestamp:** `2025-05-10T23:20:13.8688643Z`
- **Event:** The scheduled task UpdaterTask was deleted by user huy using the command "schtasks.exe" /delete /tn UpdaterTask /f.
- **Action:** Task deletion detected.
- **Initiating Process:** powershell.exe

---

## Summary

The investigation confirmed that a scheduled task named UpdaterTask was created, executed, and deleted by the user huy on the device huy. The task was created at 2025-05-10T23:19:49.4869401Z using schtasks.exe with a command that executed the notepad.exe application hourly. It was then executed at 2025-05-10T23:20:04.8675568Z and deleted shortly after at 2025-05-10T23:20:13.8688643Z. This activity suggests the possibility of a persistence mechanism being tested or used by the user or a malicious actor. The sequence of events, with immediate cleanup after execution, indicates a deliberate action, potentially as part of a larger testing or evasion strategy.

---

## Response Taken

- Monitoring: The event timeline was reviewed and confirmed that the scheduled task was indeed created, executed, and deleted by the user huy. This was done using tools like DeviceProcessEvents to analyze the system logs and detect the actions performed on the endpoint.

- Further Investigation: Given the suspicious nature of the task's creation and removal, additional investigation was initiated to determine if this was a legitimate action by the user or part of a broader malicious campaign.

- Endpoint Analysis: The endpoint will continue to be monitored for any other signs of malicious behavior or unauthorized task creation. Additional tools and techniques may be employed to ensure that the system is not compromised.

- Alerting: Alerts for unusual task creation and execution events were configured to track potential reoccurrence of similar behavior.

---
