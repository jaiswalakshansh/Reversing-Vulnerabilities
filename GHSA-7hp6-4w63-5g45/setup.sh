#!/usr/bin/env bash
#
# GHSA-7hp6-4w63-5g45 - automated lab setup (all-in-one)
# Spins up a VULNERABLE LiteLLM (v1.103.0) + Postgres in Docker and provisions a
# low-privilege internal_user you can log into the UI with. For local, authorized,
# educational use only.
#
#   ./setup.sh          # or "up": generate docker files, start the lab, provision alice
#   ./setup.sh reset    # wipe DB + restart clean (use between runs)
#   ./setup.sh down     # tear everything down and remove volumes
#
set -euo pipefail
cd "$(dirname "$0")"

# --------------------------- knobs (edit if you like) ---------------------------
IMAGE="ghcr.io/berriai/litellm:v1.103.0"       # VULNERABLE. Patched in v1.103.1.
PROXY_PORT=4000
DB_PORT=5433
MASTER_KEY="sk-1234567890abcdef"
SALT_KEY="sk-salt-static-do-not-rotate"        # the reused key at the heart of the bug
EMAIL="alice@corp.example"
PASSWORD="DemoPassw0rd!23"                      # LiteLLM requires >= 12 chars
USER_ID="alice"
PROJECT="litellm-ghsa-lab"
LAB=".lab"                                      # generated docker files live here
BASE="http://localhost:${PROXY_PORT}"
# -------------------------------------------------------------------------------

compose() { docker compose -p "$PROJECT" -f "$LAB/docker-compose.yml" "$@"; }

gen_docker_files() {
  mkdir -p "$LAB"
  # Minimal proxy config. A dummy model is enough - the exploit never calls an LLM.
  cat > "$LAB/config.yaml" <<YAML
model_list:
  - model_name: fake-gpt
    litellm_params:
      model: openai/fake
      api_key: "sk-fake-not-used"
      api_base: "http://localhost:9/v1"
litellm_settings:
  drop_params: true
general_settings:
  master_key: "${MASTER_KEY}"
YAML
  cat > "$LAB/docker-compose.yml" <<YAML
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: litellm
      POSTGRES_PASSWORD: litellm
      POSTGRES_DB: litellm
    ports: ["${DB_PORT}:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U litellm -d litellm"]
      interval: 3s
      timeout: 3s
      retries: 20
  litellm:
    image: ${IMAGE}
    depends_on:
      db:
        condition: service_healthy
    environment:
      # ONE key for two jobs (sealing secrets at rest AND minting session tokens)
      # is the whole vulnerability.
      LITELLM_MASTER_KEY: "${MASTER_KEY}"
      LITELLM_SALT_KEY: "${SALT_KEY}"
      DATABASE_URL: "postgresql://litellm:litellm@db:5432/litellm"
      STORE_MODEL_IN_DB: "true"
    ports: ["${PROXY_PORT}:4000"]
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    command: ["--config", "/app/config.yaml", "--port", "4000", "--detailed_debug"]
YAML
}

wait_healthy() {
  echo "[*] waiting for proxy at ${BASE} ..."
  for i in $(seq 1 40); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/health/liveliness" 2>/dev/null)" = "200" ]; then
      echo "[+] proxy is up"; return 0
    fi
    sleep 3
  done
  echo "[-] proxy never became healthy; check: docker compose -p ${PROJECT} -f ${LAB}/docker-compose.yml logs litellm"
  exit 1
}

provision_user() {
  echo "[*] creating internal_user '${USER_ID}' (${EMAIL}) ..."
  curl -fsS -X POST "${BASE}/user/new" \
    -H "Authorization: Bearer ${MASTER_KEY}" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"${USER_ID}\",\"user_email\":\"${EMAIL}\",\"user_role\":\"internal_user\"}" >/dev/null 2>&1 || true

  echo "[*] setting a UI password so alice can sign in at ${BASE}/ui ..."
  curl -fsS -X POST "${BASE}/user/update" \
    -H "Authorization: Bearer ${MASTER_KEY}" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"${USER_ID}\",\"user_email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"user_role\":\"internal_user\"}" >/dev/null

  # Convenience only: an unrestricted internal_user key so you can test the exploit
  # from the terminal WITHOUT the UI. (A key alice mints herself in the UI is capped
  # to LLM routes and can't reach /key/generate - see README. Her *login session*
  # key can, which is the realistic path shown in the README.)
  echo "[*] minting a quick-test key -> .attacker_key ..."
  local key
  key=$(curl -fsS -X POST "${BASE}/key/generate" \
    -H "Authorization: Bearer ${MASTER_KEY}" -H "Content-Type: application/json" \
    -d "{\"user_id\":\"${USER_ID}\",\"key_alias\":\"alice-quicktest\",\"models\":[\"fake-gpt\"]}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")
  echo "$key" > .attacker_key
}

case "${1:-up}" in
  down)
    [ -f "$LAB/docker-compose.yml" ] && compose down -v || true
    rm -f .attacker_key
    echo "[+] lab torn down."
    exit 0
    ;;
  reset)
    [ -f "$LAB/docker-compose.yml" ] && compose down -v || true
    ;;
  up|"") ;;
  *) echo "usage: $0 [up|reset|down]"; exit 2;;
esac

gen_docker_files
echo "[*] starting VULNERABLE litellm (${IMAGE}) + postgres ..."
compose up -d
wait_healthy
provision_user

cat <<EOF

======================== LAB READY (VULNERABLE) ========================
  Web UI    : ${BASE}/ui
  Email     : ${EMAIL}
  Password  : ${PASSWORD}
  Role      : internal_user   (NOT an admin)

  Quick-test key (terminal only, no UI needed):
    $(cat .attacker_key)     (also saved to ./.attacker_key)

  Next:
    1) ./listener.sh 4444                                  # terminal A
    2) python3 exploit_revshell.py --lport 4444            # terminal B (uses .attacker_key)
       ...or the realistic path: log into the UI as alice, copy her session key
       from DevTools, then:  python3 exploit_revshell.py --key sk-... --lport 4444
    3) catch a root shell in terminal A

  Tear down: ./setup.sh down
========================================================================
EOF
