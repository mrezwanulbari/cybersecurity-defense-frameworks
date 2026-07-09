# Generic Incident Response Playbook Template

A reusable skeleton for building new incident-type-specific playbooks, following the NIST SP 800-61r2 lifecycle. Copy this structure when building a playbook for an incident type not yet covered in [incident-response-playbooks](https://github.com/mrezwanulbari/incident-response-playbooks).

## Template Structure

```markdown
# [Incident Type] Response Playbook

**Scope:** [What specifically triggers this playbook]
**Framework:** NIST SP 800-61r2

## 1. Detection & Triage (Target: [time])
- Initial indicators
- Triage decisions (checklist)
- Severity classification table

## 2. Containment (Target: [time])
- Short-term containment actions
- Evidence preservation steps (parallel to containment, not after)
- Critical decision points (explicitly call out any irreversible actions)

## 3. Eradication
- Root cause identification
- Persistence mechanism removal
- Vector closure before reconnection

## 4. Recovery
- Validation steps before restoring
- Staged recovery order
- Post-recovery monitoring period

## 5. Post-Incident Activity
- Lessons-learned review timing
- Detection rule updates
- Playbook update triggers

## Escalation Contacts
[Organization-specific — IR lead, legal, executive sponsor, insurance carrier]
```

## Why a Consistent Template Matters

Analysts working an incident at 2am shouldn't have to figure out a new document structure on top of figuring out the incident itself. A consistent template across all playbooks means muscle memory transfers — someone trained on the ransomware playbook can pick up the phishing playbook and immediately know where to find the containment checklist.

---
*Part of the [cybersecurity-defense-frameworks](../README.md) repository.*
