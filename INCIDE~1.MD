# Multi-Vector Attack Correlation — SSH Brute Force & Web Reconnaissance

**Analyst:** Daniel Agbosua · SOC Analyst
**Investigation date:** 22-09-2026 · **Incident date:** 04-09-2026
**Environment:** LearnCyber (training/lab)

## Executive summary

The investigation identified malicious activity against LearnCyber surfaces from the **195.178.110.0/24** network. This included repeated failed SSH authentication attempts against the `root` account from **195.178.110.228**, and a separate Cloudflare-blocked web request from **195.178.110.15** targeting `/wp-config.php-backup`.

The two events occurred approximately **3 seconds apart** (SSH authentication failure at 14:30:42; Cloudflare block at 14:30:45), and the source IPs share common infrastructure — the same ISP, **TECHOFF SRV LIMITED**, across adjacent ASNs **AS48089** (.228) and **AS48090** (.15, .30). The evidence supports **broader reconnaissance / multi-vector malicious activity, with medium confidence**. No successful SSH authentication or successful retrieval of the targeted web resource was identified.

## Alert triage

| Field | Value |
|---|---|
| Primary SSH source IP | 195.178.110.228 |
| Web attack source IP | 195.178.110.15 |
| Target system | soc |
| Target account | root |
| Authentication method | SSH |
| Authentication result | Failed |
| Rule description | PAM: user login failed |
| Severity | 5 (individual PAM failure) |

## Host investigation

This was not a single failed login but multiple attempts across several minutes. It was **not** password spraying — a single `root` account was hit repeatedly, which confirms **brute force / password guessing**. The mechanics are clearly automated/bot-driven (rapid connect–fail–disconnect, sequential source ports, machine-like timing). **No compromise** was identified.

## Incident timeline (Sep 04, BST)

| Time | Source | IP | Activity |
|---|---|---|---|
| 14:25:39 | Attacker | 195.178.110.228 | Connection closed — port 33318 (initial probe) |
| 14:28:57 | Attacker | 195.178.110.228 | Authentication failure (user=root) |
| 14:29:00 | Attacker | 195.178.110.228 | Failed password for root — port 36664 (attempt 1) |
| 14:29:01 | Attacker | 195.178.110.228 | Connection closed [preauth] — port 36664 |
| 14:30:42 | Attacker | 195.178.110.228 | Authentication failure (user=root) |
| 14:30:44 | Attacker | 195.178.110.228 | Failed password for root — port 39892 (attempt 2) |
| 14:30:44 | Attacker | 195.178.110.228 | Connection closed [preauth] — port 39892 |
| 14:30:45 | Attacker | 195.178.110.15 | Cloudflare WAF blocked GET /wp-config.php-backup |
| 14:32:32 | Attacker | 195.178.110.228 | Authentication failure (user=root) |
| 14:32:35 | Attacker | 195.178.110.228 | Failed password for root — port 43078 (attempt 3) |
| 14:32:36 | Attacker | 195.178.110.228 | Connection closed [preauth] — port 43078 |
| 14:33:40 | Analyst | localhost | Investigation: grep 195.178.110.228 /var/log/auth.log |
| 14:34:16 | Analyst | localhost | Investigation: grep 195.178.110.228 /var/log/auth.log |
| Post-incident | Analyst | localhost | Containment: ufw deny from 195.178.110.0/24 to any |

## Threat intelligence

Examined via VirusTotal, GreyNoise, AbuseIPDB, and Shodan. All three IPs: ISP **TECHOFF SRV LIMITED**, Netherlands, **100% AbuseIPDB confidence of abuse**.

| IP | ASN | Vendors flagging | AbuseIPDB reports | Scanner categories | OS (Shodan) |
|---|---|---|---|---|---|
| 195.178.110.228 | AS48089 | 15/89 | 52,135 (1,775 sources) | Brute force, SSH, hacking, port scan, web app attack | Linux |
| 195.178.110.30 | AS48090 | 10/89 | 422,921 (596 sources) | Brute force, SSH, port scan, web app attack | Ubuntu |
| 195.178.110.15 | AS48090 | 14/89 | 178,665 (1,836 sources) | Brute force, hacking, port scan, bad web bot, web app attack | Linux |

## MITRE ATT&CK mapping

- **T1110.001 Password Guessing — Confirmed.** Repeated SSH password failures against root in auth.log.
- **T1595 Active Scanning — Potentially applicable.** Threat-intel associates the sources with scanning; not confirmed against LearnCyber telemetry.
- **T1190 Exploit Public-Facing Application — Potential, not confirmed.** The `/wp-config.php-backup` request was blocked; a probe is not proof of successful exploitation.

## Containment & remediation

Contained via `ufw deny from 195.178.110.0/24`. Full SSH, web, monitoring, and long-term detection-engineering recommendations are documented separately (see `remediation.md`).

## Final analyst verdict

**Broader reconnaissance / multi-vector malicious activity against LearnCyber — medium confidence.** The temporal, behavioural, and infrastructure correlations are meaningful and rule out an isolated event, but the evidence does not conclusively prove a single threat actor. **No successful SSH compromise and no successful retrieval of the WordPress backup file were identified in the reviewed evidence.**
