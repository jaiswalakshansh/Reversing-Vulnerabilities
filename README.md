# Reversing-Vulnerabilities

Hands-on labs that reverse-engineer publicly disclosed vulnerabilities: understand the
root cause and code flow, then reproduce the exploit end to end in a self-contained,
local Docker environment.

> For local, authorized, educational use only. Everything runs against your own
> machine. Never point any technique here at systems you don't own.

## Labs

| Lab | Vulnerability | Impact | Advisory |
|---|---|---|---|
| [GHSA-7hp6-4w63-5g45](GHSA-7hp6-4w63-5g45/) | LiteLLM — cross-domain reuse of the salt key | `internal_user` → `proxy_admin` → RCE (CVSS 9.9) | [GHSA-7hp6-4w63-5g45](https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45) |
| [CVE-2026-108097](CVE-2026-108097/) | Drupal core Field UI — render-array `#region_callback` injection | Unauthenticated RCE (CVSS 9.8) | [SA-CORE-2026-014](https://www.drupal.org/sa-core-2026-014) |
| [CVE-2026-109618-109619](CVE-2026-109618-109619/) | PHP core "PHP2Shell" — request-startup state corruption via bailout (CVSS 9.2), fixed in 8.4.27 | Worker-pool exhaustion demonstrated on vulnerable 8.4.26; no public RCE; the leaked bucket-pointer writeup was wrong | [php.net security release](https://www.php.net/archive/2026.php) |

Each lab folder has its own `README.md` with the full write-up (why it's a vulnerability +
step-by-step reproduction) and an automated `setup.sh` to stand up the vulnerable version.
