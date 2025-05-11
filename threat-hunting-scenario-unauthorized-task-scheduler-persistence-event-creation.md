# Threat Event (Unauthorized Task Scheduler Persistence)
**User-created Malicious Scheduled Task**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Open Command Prompt and create a scheduled task that runs a fake script every hour:
schtasks /create /tn "UpdaterTask" /tr "notepad.exe" /sc hourly /f
2. Wait a few minutes and let the task run silently in the background.
3. Manually run the task:
schtasks /run /tn "UpdaterTask"
4. Delete the task:
schtasks /delete /tn "UpdaterTask" /f

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table |
| **Purpose**| 	Detects the creation/execution/deletion of the scheduled task (schtasks.exe). |

---

## Related Queries:
```kql
// Look for the creation/execution/deletion of scheduled tasks
DeviceProcessEvents
| where DeviceName == "huy"
| where FileName in~ ("schtasks.exe", "powershell.exe")
| where ProcessCommandLine has_any ("create", "schedule", "schtasks", "register-scheduledtask")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/](https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 10, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 10, 2025  | Huy Tang  
