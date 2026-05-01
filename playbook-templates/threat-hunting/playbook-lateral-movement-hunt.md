# Threat Hunting Playbook: Lateral Movement Detection

**Author:** Shakil Md. Rezwanul Bari  
**Version:** 1.0  
**MITRE ATT&CK:** T1021, T1570, T1072  
**Hypothesis:** An adversary has gained initial access and is moving laterally through the network using legitimate credentials and remote services.

## Hunt Scope
- Windows Active Directory environments
- Time Range: Last 30 days
- Data Sources: Windows Event Logs, EDR telemetry, network flow data, authentication logs

## Hunt Queries

### 1. Anomalous RDP Sessions (Splunk SPL)
```spl
index=wineventlog EventCode=4624 LogonType=10
| stats count dc(TargetUserName) as unique_users values(TargetUserName) as users by SourceIP
| where count > 5 AND unique_users > 2
| sort -count
```

### 2. PsExec/Remote Service Installation
```spl
index=wineventlog EventCode=7045 ServiceName=PSEXESVC OR ServiceName=csexec*
| table _time ComputerName ServiceName ServiceFileName AccountName
| sort -_time
```

### 3. Pass-the-Hash Detection
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| stats count by TargetUserName SourceIP WorkstationName
| where count > 10
| sort -count
```

### 4. WMI Remote Execution
```spl
index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
| table _time ComputerName User Image CommandLine ParentCommandLine
| sort -_time
```

### 5. Anomalous SMB File Shares Access
```spl
index=wineventlog EventCode=5140
| stats count dc(ShareName) as shares_accessed values(ShareName) by SubjectUserName SourceAddress
| where shares_accessed > 5
| sort -shares_accessed
```

## Investigation Steps
1. Identify the initial compromised account/system
2. Map all lateral movement paths (source → destination)
3. Correlate with authentication anomalies
4. Check for credential dumping indicators (LSASS access)
5. Look for data staging on intermediate systems
6. Assess if threat actor reached critical assets

## Expected Outcomes
- Map of lateral movement paths
- List of compromised accounts and systems
- Identification of initial access vector
- Containment recommendations

## Compliance Mapping
| Framework | Control |
|-----------|---------|
| NIST 800-53 | SI-4, AU-6, IR-4 |
| PCI-DSS v4.0.1 | 10.4, 10.6, 11.5 |
| MITRE D3FEND | D3-LAM, D3-NTA |
