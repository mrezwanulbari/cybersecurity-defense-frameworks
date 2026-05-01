# PCI-DSS v4.0.1 Continuous Compliance Monitoring Template

**Author:** Shakil Md. Rezwanul Bari  
**Version:** 1.0  
**Framework:** PCI-DSS v4.0.1  
**Last Updated:** 2025-07-01

## Overview
This template provides automated compliance monitoring configurations for PCI-DSS v4.0.1 using SIEM correlation rules and dashboards. Developed from hands-on implementation that achieved 80% security posture improvement at a major banking institution.

## Requirement Monitoring Matrix

### Requirement 1: Network Security Controls
| Sub-Req | Monitoring Rule | SIEM Query |
|---------|----------------|------------|
| 1.2.1 | Firewall rule change detection | `index=firewall action=rule_change \| stats count by admin_user rule_name` |
| 1.2.5 | Unauthorized service detection | `index=network dest_port!=allowed_ports \| stats count by src_ip dest_ip dest_port` |
| 1.4.2 | Inbound traffic to CDE | `index=firewall direction=inbound dest_zone=CDE \| stats count by src_ip action` |

### Requirement 5: Malware Protection
| Sub-Req | Monitoring Rule | SIEM Query |
|---------|----------------|------------|
| 5.2.1 | AV/EDR status monitoring | `index=endpoint av_status!=active \| table hostname av_status last_update` |
| 5.3.1 | Malware detection events | `index=endpoint category=malware \| stats count by hostname malware_name action` |
| 5.3.4 | Audit log integrity | `index=endpoint log_tamper=true \| table hostname event_time details` |

### Requirement 8: Access Management
| Sub-Req | Monitoring Rule | SIEM Query |
|---------|----------------|------------|
| 8.3.4 | Failed auth monitoring | `index=auth action=failure \| stats count by user src_ip \| where count>5` |
| 8.3.6 | MFA enforcement check | `index=auth mfa_used=false dest_zone=CDE \| table user src_ip timestamp` |
| 8.6.1 | Shared account usage | `index=auth user=shared_* OR user=generic_* \| stats count by user src_ip` |

### Requirement 10: Logging & Monitoring
| Sub-Req | Monitoring Rule | SIEM Query |
|---------|----------------|------------|
| 10.2.1 | User access to CHD | `index=app category=cardholder_data \| stats count by user action data_type` |
| 10.4.1 | Audit log review | Automated daily dashboard review with anomaly detection |
| 10.7.1 | Log collection failures | `index=_internal log_level=ERROR component=forwarder \| stats count by host` |

### Requirement 11: Security Testing
| Sub-Req | Monitoring Rule | SIEM Query |
|---------|----------------|------------|
| 11.3.1 | Vulnerability scan results | `index=vuln_scan severity=critical OR severity=high \| stats count by host vuln_name` |
| 11.5.1 | IDS/IPS alert monitoring | `index=ids_ips \| stats count by signature severity action src_ip dest_ip` |
| 11.6.1 | Change detection alerts | `index=fim action=modified file_path=critical_* \| table host file_path change_type` |

## Dashboard Configuration
Create a PCI-DSS v4.0.1 compliance dashboard with panels for:
1. **Compliance Score** — overall percentage based on passing controls
2. **Critical Findings** — count of critical/high severity items
3. **Authentication Anomalies** — failed logins, MFA bypasses, shared accounts
4. **Network Security** — unauthorized traffic, firewall changes
5. **Malware Events** — detections, containment status
6. **Data Access** — cardholder data access patterns
7. **Log Health** — collection status, gaps, integrity

## Automation Recommendations
- Schedule daily compliance reports via SOAR
- Auto-create tickets for critical compliance violations
- Integrate with GRC platform for evidence collection
- Set up real-time alerts for Requirement 10 violations
