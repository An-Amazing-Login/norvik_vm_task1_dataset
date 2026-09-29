# Norvik Home A/S — Vulnerability Management Standard (excerpt)

Document owner: IT Security · Version 1.3 · Approved 2024-08-19 · Next review: 2025-08-19

## 1. Scope
All IT assets owned or operated by Norvik Home in the Nordic region: HQ data centre, HQ DMZ, Azure (West Europe), stores in Denmark, Sweden, Norway and Finland, and employee endpoints.

Scanning methods:
- Laptops and store back-office PCs: scanner agent, reporting daily.
- Servers, network devices and hypervisors: weekly network scan from the HQ scanner appliance, using service-account credentials where configured.
- POS terminals are out of scope for internal scanning (see exception EXC-0003).

## 2. Severity and remediation deadlines
Severity is taken directly from the scanner (CVSS v3 base score of the finding).

| Severity | CVSS v3 | Remediation deadline from first detection |
| --- | --- | --- |
| Critical | 9.0–10.0 | 14 days |
| High | 7.0–8.9 | 30 days |
| Medium | 4.0–6.9 | 90 days |
| Low | 0.1–3.9 | 180 days |

The asset owner (owner_team in the CMDB) is responsible for remediation.

## 3. Exceptions
If a finding cannot be remediated within the deadline, the asset owner may request an exception. Exceptions must be approved by the requesting team's manager or by IT Security, must state a justification, and should have an expiry date no more than 12 months after approval. Exceptions are recorded in the exception register.

## 4. Reporting
IT Security publishes a monthly report to IT management and the Security Steering Committee containing:
- **Open findings**: the number of open findings in the scanner, by severity.
- **SLA compliance**: the share of open findings whose age (export date minus first_seen) is within the remediation deadline. Findings covered by an exception with status Active are excluded.
- **MTTR**: the mean number of days from first_seen to fixed_date, for findings fixed in the last 30 days.

---

# Monthly Vulnerability Report — September 2026 (data export 2026-09-21)

| Metric | Value |
| --- | --- |
| Open findings | 14,079 |
| — Critical | 3,842 |
| — High | 8,155 |
| — Medium | 1,323 |
| — Low | 759 |
| SLA compliance | 17.9 % |
| MTTR (findings fixed in the last 30 days) | 28.1 days |
| Assets scanned | 1,748 |

Scanner dashboard, "Vulnerabilities (CVE instances)": 1,037,015.

Comments from IT Security: SLA compliance remains low. Asset owners are reminded to prioritise Critical findings.
