# Containment & Remediation

## Pre-check
- Confirm no successful/ongoing login before hardening:
  `grep -Ei "Accepted|session opened" /var/log/auth.log` (empty output = clean host).

## Immediate actions
- Confirm no SSH brute-force / password guessing is still ongoing.
- Confirm all authentication status and review privileged-account activity.
- Block confirmed malicious IPs (done: `ufw deny from 195.178.110.0/24 to any`).
- Continue monitoring Cloudflare security events.

## Short-term — SSH hardening
- **Disable direct root SSH login** (`PermitRootLogin no`).
- **Enforce key-only auth** — disable passwords entirely (`PasswordAuthentication no`, `PubkeyAuthentication yes`); add the admin key first.
- **Automatic lockout** for repeated failures (Fail2ban `sshd` jail).
- **Restrict SSH access** to allowlisted admin IPs or a VPN, rather than relying only on subnet blocking.
- **Review UFW:** confirm default-deny inbound, the `195.178.110.0/24` deny rule is active, and SSH is limited to trusted IPs.

## Short-term — web security
- **Remove backup/config files** from the web root (`.bak`, `.old`, `.save`, `~`, `.swp`, `*config*backup*`).
- **Restrict origin to Cloudflare IP ranges** so the WAF cannot be bypassed via the origin IP.
- **Keep Cloudflare WAF managed rules in Block mode** (not log-only).
- **Rate-limit common scanner paths** (`wp-login.php`, `xmlrpc.php`, `/wp-admin`).
- **Rotate secrets** as a precaution: WordPress database password and salts/keys.

## Monitoring
- **Correlate Cloudflare and SSH telemetry by source IP and ASN** to catch coordinated, multi-vector activity from a single operator earlier — as seen in this incident.

## Long-term — detection engineering
1. Wazuh rules for repeated authentication failures against privileged accounts.
2. Correlate SSH authentication events with source-IP reputation.
3. Forward Cloudflare security telemetry into the SIEM.
4. Correlation rules for simultaneous web + infrastructure attacks from one source/subnet.
5. Auto-enrich alerts with threat intelligence.
6. Monitor for repeat activity from known-malicious infrastructure (e.g., AS48089 / AS48090, TECHOFF SRV LIMITED).
7. Document an incident-response procedure for multi-vector attacks.
