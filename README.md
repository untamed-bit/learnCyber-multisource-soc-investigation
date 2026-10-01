# Multi-Source SOC Investigation: Detecting & Correlating Web and SSH Attacks

> Correlating Cloudflare WAF events, Linux SSH authentication logs, and Wazuh SIEM telemetry to determine whether low-severity events across separate layers were part of a single, broader attack.

**Analyst:** Daniel Agbosua · SOC Analyst
**Type:** Hands-on SOC investigation (lab / training environment — LearnCyber)
**Outcome:** Confirmed multi-vector reconnaissance from a single hosting operator, contained the malicious sources, and produced detection-engineering recommendations.

---

## Project overview

I investigated real malicious activity targeting the LearnCyber infrastructure by correlating three independent telemetry sources — **Cloudflare WAF security events, Linux SSH authentication logs, and Wazuh SIEM alerts**. Each event, viewed alone, looked like routine low-severity noise. The goal was to test whether *correlating across sources* revealed a broader pattern that individual alerts would miss.

It did: an SSH brute-force campaign against `root` and a WordPress config-file probe originated from the **same hosting operator (TECHOFF SRV LIMITED, AS48089–AS48090, Netherlands)** within seconds of each other — evidence of coordinated, multi-vector reconnaissance rather than isolated events.

---

## Skills demonstrated

- SIEM monitoring & alert triage (**Wazuh**)
- Linux authentication log analysis (`/var/log/auth.log`)
- Web application firewall event analysis (**Cloudflare WAF**)
- Threat-intelligence enrichment (**AbuseIPDB, VirusTotal, GreyNoise, Shodan**)
- **Cross-source correlation** (web + host + SIEM)
- Incident timeline construction
- **MITRE ATT&CK** mapping (with confirmed vs. potential rigor)
- Firewall containment (**UFW**)
- Detection-engineering & remediation recommendations
- Clear, evidence-based investigation reporting

---

## Environment & tooling

| Layer | Tool |
|---|---|
| SIEM | Wazuh |
| Web security | Cloudflare WAF |
| Operating system | Ubuntu Linux |
| Threat intelligence | AbuseIPDB, VirusTotal, GreyNoise, Shodan |
| Host firewall | UFW |
| Framework | MITRE ATT&CK |

---

## The problem

Security events were appearing across multiple layers of the infrastructure. Individually, each looked relatively low severity — a handful of failed SSH logins here, a single blocked web request there. The investigation set out to answer one question:

> **Do these events correlate into a broader attack pattern, or are they unrelated background noise?**

---

## Methodology

A repeatable six-step investigation loop: **Understand → Scope → Correlate → Enrich → Decide → Document.**

1. Triaged the Wazuh authentication alert (`PAM: user login failed`, target `root`).
2. Pulled and analysed the raw Linux `/var/log/auth.log` evidence.
3. Identified the pattern: repeated SSH authentication failures against a single privileged account.
4. Analysed the Cloudflare WAF event targeting a sensitive WordPress file.
5. Enriched all source IPs with four threat-intelligence platforms.
6. Correlated activity across web and host layers, built a timeline, mapped to MITRE ATT&CK, and contained the sources.

---

## Key findings

### 1. SSH brute-force against `root` (Wazuh + auth.log)

Source **195.178.110.228** made repeated SSH password attempts against `root` — three complete failure cycles over ~7 minutes, each from a new source port, at machine-like ~90-second intervals.

- **Not** a single failed login, **not** password spraying (same account hit repeatedly) → **classic brute-force / password guessing.**
- Automated, bot-driven (rapid connect → fail → disconnect, sequential ephemeral ports).
- **No successful authentication** — every attempt ended in failure or `[preauth]` close.

### 2. WordPress config probe (Cloudflare WAF)

Source **195.178.110.15** sent `GET /wp-config.php-backup` — an attempt to retrieve a backup of WordPress's configuration file, which (unlike the live `.php`) can be served as plaintext and expose **database credentials and auth salts**.

- Blocked by the Cloudflare Managed rule **"WordPress – Broken Access Control, File Inclusion"** (Action: **Block**).
- Request **did not reach the origin** — origin protected at the edge.

### 3. The correlation

The Cloudflare block at **14:30:45** landed **~3 seconds after** an SSH authentication failure at **14:30:42** — and both source IPs belong to the **same ISP, TECHOFF SRV LIMITED (adjacent ASNs AS48089 / AS48090), Netherlands.** Two different attack surfaces, one operator, near-simultaneous timing.

### Incident timeline (key events, Sep 04)

| Time (BST) | Source | IP | Activity |
|---|---|---|---|
| 14:25:39 | Attacker | 195.178.110.228 | Initial connection / probe (port 33318) |
| 14:29:00 | Attacker | 195.178.110.228 | Failed password for **root** (port 36664 — attempt 1) |
| 14:30:42 | Attacker | 195.178.110.228 | SSH authentication failure |
| 14:30:44 | Attacker | 195.178.110.228 | Failed password for **root** (port 39892 — attempt 2) |
| **14:30:45** | Attacker | **195.178.110.15** | **Cloudflare blocks `GET /wp-config.php-backup`** |
| 14:32:35 | Attacker | 195.178.110.228 | Failed password for **root** (port 43078 — attempt 3) |
| 14:33–14:34 | Analyst | localhost | Investigation (`grep` auth.log) |
| Post-incident | Analyst | localhost | `ufw deny from 195.178.110.0/24` — containment |

*(Full timeline: [`timeline.csv`](timeline.csv))*

### Threat intelligence

All three IPs resolved to **TECHOFF SRV LIMITED, Netherlands**, each with **100% AbuseIPDB confidence of abuse**:

| IP | ASN | Vendors flagging | AbuseIPDB reports | Scanner categories |
|---|---|---|---|---|
| 195.178.110.228 | AS48089 | 15/89 | 52,135 | Brute force, SSH, hacking, port scan, web app attack |
| 195.178.110.30 | AS48090 | 10/89 | 422,921 | Brute force, SSH, port scan, web app attack |
| 195.178.110.15 | AS48090 | 14/89 | 178,665 | Brute force, hacking, port scan, bad web bot, web app attack |

---

## MITRE ATT&CK mapping

| Technique | ID | Status |
|---|---|---|
| Password Guessing | T1110.001 | **Confirmed** |
| Active Scanning | T1595 | Potentially applicable |
| Exploit Public-Facing Application | T1190 | Potential, not confirmed |

*Full reasoning: [`mitre-mapping.md`](mitre-mapping.md). Only what the evidence proves is marked "Confirmed" — a blocked probe is not a successful exploit.*

---

## Verdict

**Broader reconnaissance / multi-vector malicious activity against LearnCyber — medium confidence.**

The temporal (~3 s), behavioural (multi-surface), and infrastructure (shared ISP / adjacent ASNs) correlations are meaningful and rule out "isolated event." Confidence is **medium**, not high, because the evidence does not conclusively prove all activity came from a single threat actor. **No successful SSH compromise and no successful retrieval of the WordPress backup file** were identified.

---

## Containment & remediation

Contained via UFW (`deny from 195.178.110.0/24`). Full hardening plan — SSH, web, monitoring, and long-term detection engineering — in [`remediation.md`](remediation.md).

---

## What this project demonstrates

Individually, these were three forgettable alerts. Correlated, they told a coherent story: a single hostile operator probing multiple attack surfaces of the same target within seconds. **The core skill on display is not running one tool — it's fusing evidence across web, host, and SIEM layers to see what any single source would have missed, and reporting it with calibrated confidence.**

---

## Repository contents

| File | Description |
|---|---|
| `README.md` | This overview |
| `incident-report.pdf` | Full investigation report |
| `timeline.csv` | Complete incident timeline |
| `mitre-mapping.md` | MITRE ATT&CK technique mapping with evidence |
| `remediation.md` | Containment and remediation recommendations |
| `evidence/` | Sanitised screenshots (Wazuh, SSH logs, Cloudflare, threat intel) |

---

*Environment note: conducted in the LearnCyber training/lab environment. IP addresses shown are attacker-side public indicators (safe to publish); no production or personal data is included.*
