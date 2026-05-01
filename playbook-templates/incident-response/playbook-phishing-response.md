# Phishing Incident Response Playbook

**Author:** Shakil Md. Rezwanul Bari  
**Version:** 1.0  
**Last Updated:** 2025-07-01  
**MITRE ATT&CK:** T1566.001, T1566.002  
**MITRE D3FEND:** D3-MFA, D3-URA, D3-FCR  
**Severity:** High  
**Automation Level:** Semi-Automated (SOAR-integrated)

## Overview
This playbook provides a standardized, repeatable procedure for responding to phishing incidents. It is designed to be framework-agnostic and adaptable across industries — from financial services to cloud technology to international development organizations.

## Trigger Conditions
- User-reported suspicious email
- SIEM alert: Email security gateway detection
- SOAR auto-triage: Phishing indicators matched
- Threat intelligence feed match on sender domain/IP

## Phase 1: Detection & Triage (Target: <5 minutes)

### Automated Steps (SOAR)
1. **Extract IOCs** from reported email:
   - Sender address and domain
   - Reply-to address
   - Subject line
   - URLs (defanged)
   - Attachment hashes (MD5, SHA256)
   - Email headers (X-Originating-IP, SPF/DKIM/DMARC results)
2. **Enrich IOCs** via threat intelligence feeds:
   - Check sender domain against AlienVault OTX, RiskIQ, VirusTotal
   - Check URLs against URLhaus, PhishTank
   - Check attachment hashes against VirusTotal, Hybrid Analysis
3. **Classify severity:**
   - Critical: Credential harvesting targeting executive accounts
   - High: Malware attachment or active phishing page
   - Medium: Generic phishing with known indicators
   - Low: Spam/marketing misidentified as phishing

### Analyst Decision Point
- If Critical/High → proceed to Phase 2 immediately
- If Medium → proceed to Phase 2 within 30 minutes
- If Low → close with user notification

## Phase 2: Containment (Target: <15 minutes)

### Automated Steps (SOAR)
1. **Block sender** at email gateway (Exchange/O365/Google Workspace)
2. **Block malicious URLs** at web proxy/firewall
3. **Quarantine matching emails** across all mailboxes (search & purge)
4. **Disable compromised accounts** (if credentials were entered)
5. **Block attachment hashes** at endpoint protection (EDR)

### Analyst Steps
6. Review quarantine results — confirm all instances removed
7. Check if any users clicked links or opened attachments
8. If credentials compromised → trigger **Credential Compromise sub-playbook**
9. If malware executed → trigger **Malware Response sub-playbook**

## Phase 3: Investigation (Target: <2 hours)

1. **Analyze email headers** for origination path and infrastructure
2. **Sandbox analysis** of attachments (Hybrid Analysis, Any.Run, Joe Sandbox)
3. **URL analysis** — screenshot landing pages, check for credential harvesting forms
4. **Log correlation** in SIEM:
   - DNS queries to phishing domains
   - Web proxy logs showing URL access
   - Authentication logs for compromised credentials
   - Endpoint logs for malware execution
5. **Determine scope:** How many users received the email? How many interacted?
6. **Attribution** — map TTPs to MITRE ATT&CK; check for known threat actor patterns

## Phase 4: Eradication & Recovery

1. Confirm all malicious emails purged from environment
2. Reset credentials for any compromised accounts
3. Force MFA re-enrollment for affected users
4. Remove any persistence mechanisms from compromised endpoints
5. Update email filtering rules to prevent similar attacks
6. Add new IOCs to internal threat intelligence platform

## Phase 5: Post-Incident

1. **Document timeline** of events and response actions
2. **Calculate metrics:** Time to detect, time to contain, time to resolve
3. **User notification:** Send security awareness reminder to affected users
4. **Lessons learned:** Update detection rules if gaps identified
5. **Playbook update:** Revise this playbook based on findings
6. **Report:** Generate incident report for management/compliance

## Key Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to Detect | <5 min | Alert to analyst acknowledgment |
| Time to Contain | <15 min | Acknowledgment to containment complete |
| Time to Resolve | <4 hours | Detection to full eradication |
| User Impact | <1% | Percentage of users who interacted |

## SOAR Integration Points
- **Cortex XSOAR:** Phishing - Generic v3 playbook (customized)
- **Splunk SOAR:** Phishing Investigation workflow
- **ServiceNow:** Automated incident ticket creation

## Compliance Mapping
| Framework | Control |
|-----------|---------|
| NIST 800-53 | IR-4, IR-5, IR-6, SI-3, SI-8 |
| PCI-DSS v4.0.1 | 5.2, 5.3, 10.6, 12.10 |
| ISO 27001 | A.16.1.2, A.16.1.4, A.16.1.5 |
