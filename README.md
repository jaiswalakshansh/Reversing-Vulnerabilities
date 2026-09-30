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

Each lab folder has its own `README.md` with the full write-up (why it's a vulnerability +
step-by-step reproduction) and an automated `setup.sh` to stand up the vulnerable version.
