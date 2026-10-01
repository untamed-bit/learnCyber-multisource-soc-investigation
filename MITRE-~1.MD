# MITRE ATT&CK Mapping

Techniques observed in this investigation, mapped with an explicit **status** so that only evidence-backed claims are marked confirmed. A blocked probe or a threat-intel label is *not* proof of a successful technique.

| Technique | ID | Tactic | Status |
|---|---|---|---|
| Password Guessing | T1110.001 | Credential Access | **Confirmed** |
| Active Scanning | T1595 | Reconnaissance | Potentially applicable |
| Exploit Public-Facing Application | T1190 | Initial Access | Potential, not confirmed |

---

## T1110.001 — Password Guessing — **Confirmed**

**Evidence:** `/var/log/auth.log` shows repeated SSH password-authentication failures against the `root` account from 195.178.110.228 — three complete failure cycles, each from a new source port, at machine-like intervals. This is the strongest and only fully confirmed mapping in the investigation.

## T1595 — Active Scanning — Potentially applicable

**Evidence:** Threat intelligence (AbuseIPDB, GreyNoise, Shodan) associates the source IPs with scanning activity, including port scanning and "bad web bot" categories. However, threat-intel classification alone does not prove active scanning occurred *against LearnCyber*. Additional LearnCyber-side telemetry (e.g., firewall/connection logs showing enumeration) would be required to confirm.

## T1190 — Exploit Public-Facing Application — Potential, not confirmed

**Evidence:** The Cloudflare event was a `GET /wp-config.php-backup` request, blocked by the managed rule "WordPress – Broken Access Control, File Inclusion." Requesting a sensitive file is a probe, **not** proof of successful exploitation — the request never reached the origin and returned no data. T1190 is therefore only *potentially* applicable to the web vector and is not presented as confirmed.

---

*Analyst principle: map to what the evidence proves. Over-mapping (treating every malicious URL as a successful exploit) inflates severity and erodes trust in the report.*
