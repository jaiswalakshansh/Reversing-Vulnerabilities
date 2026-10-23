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
| [CVE-2026-109618-109619](CVE-2026-109618-109619/) | PHP core "PHP2Shell" — four bailout/state-corruption bugs under two CVEs (CVSS 9.2), fixed in 8.4.27 | **RCE reproduced** on 8.4.26 with a public exploit, refused by 8.4.27; worker-pool DoS variant; [WAF rules](CVE-2026-109618-109619/WAF-RULES.md) for Cloudflare, AWS, ModSecurity, Nginx | [php.net security release](https://www.php.net/archive/2026.php) |
| [CVE-2026-110264](CVE-2026-110264/) | GitLab CE/EE — Onigmo regex-compiler integer overflow (Ruby 3.4.11, pre-fix) | Unauthenticated RCE (CVSS 10.0); lab reproduces the 2 GB unroll, the out-of-bounds regex-VM program counter (SIGSEGV), and the upstream fix's effect | [GitLab patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) |
| [CVE-2026-111497](CVE-2026-111497/) | Google Brotli 1.0.3–1.2.0 decoder desync, bundled by Node 22/24/26 (CVSS 9.2; not a Node bug) | **RCE reproduced in-lab** (network-only `id` output) on a Node 24.9.0 worker-fetch lab; patched control rejects with `-17`. Also deterministic pre-auth DoS on inbound (`Content-Encoding: br`) and outbound (`fetch()`) paths, plus the Python/Bun/distro surface | [Node security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |

Each lab folder has its own `README.md` with the full write-up (why it's a vulnerability +
step-by-step reproduction) and an automated `setup.sh` to stand up the vulnerable version.
