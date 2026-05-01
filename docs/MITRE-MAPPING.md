# MITRE ATT&CK Mapping Reference

## Detection Rules Coverage

| Technique | ID | Rule File | Severity |
|-----------|------|-----------|----------|
| Brute Force | T1110 | sigma-rules/credential-access/brute_force_auth_failures.yml | High |
| Remote Services: SMB | T1021.002 | sigma-rules/lateral-movement/suspicious_psexec_usage.yml | High |
| Exploit Public-Facing App | T1190 | sigma-rules/web-attacks/sql_injection_detection.yml | High |
| Exfiltration Over C2 | T1048 | sigma-rules/exfiltration/dns_tunneling_detection.yml | Medium |
| Scheduled Task | T1053.005 | sigma-rules/persistence/scheduled_task_creation.yml | High |
| Data Encrypted for Impact | T1486 | yara-rules/malware/ransomware_indicators.yar | Critical |
| Web Shell | T1505.003 | yara-rules/webshells/php_webshell_detection.yar | Critical |
| Application Layer Protocol | T1071.001 | yara-rules/exploits/cobalt_strike_beacon.yar | Critical |

## D3FEND Defensive Technique Mapping

| Defensive Technique | D3FEND ID | Applied In |
|---------------------|-----------|------------|
| Authentication Event Thresholding | D3-AET | Brute force detection |
| File Content Rules | D3-FCR | Phishing response playbook |
| Scheduled Job Analysis | D3-SJA | Persistence detection |
| Network Traffic Analysis | D3-NTA | Lateral movement hunting |
| Malware Analysis | D3-MA | Malware response playbook |
