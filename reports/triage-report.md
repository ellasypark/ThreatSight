# Detection Triage Report

- Generated: 2026-06-20 09:40 UTC
- Source: `data/sample/access.log`
- Events analysed: 460
- Signature detections: 1  |  Behavioral anomalies: 1

---

## Signature detections (known TTPs)

### [P1] Credential Stuffing — 45.143.220.81
- **ATT&CK:** [T1110.004 Credential Stuffing](https://attack.mitre.org/techniques/T1110/004) (Tactic: Credential Access)
- **Activity:** 149 failed / 150 logins in 1 min, scripted: True
- **Outcome:** 1 success during burst → account compromise suspected
- **Confidence:** 0.99
- **Action:** reset/kill sessions for accounts hit from 45.143.220.81; block the IP

---

## Behavioral anomalies (unknown / no signature)

### [P3] Anomalous source — 185.220.101.5
- **Why flagged:** unusually high request volume, high 404 rate, probing many distinct paths, high error rate
- **Behaviour:** 90 requests, 14 distinct paths, 404 ratio 1.0, scripted: True
- **Candidate ATT&CK:** [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002) (Tactic: Reconnaissance) — *candidate, needs analyst review*
- **Confidence:** 0.95
- **Action:** investigate 185.220.101.5; no known signature matched — possible novel/recon activity
