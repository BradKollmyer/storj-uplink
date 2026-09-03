#!/usr/bin/env bash
# Start/stop the Postgres that local storj-sim talks to (host port 5433).
# Uses Docker or Apple Container (`container` CLI). On macOS, prefers Apple
# Container when installed; elsewhere prefers Docker. Override with
# CONTAINER_ENGINE=docker or CONTAINER_ENGINE=container.
set -euo pipefail

NAME="${STORJ_SIM_PG_NAME:-storj-sim-pg}"
IMAGE="${STORJ_SIM_PG_IMAGE:-postgres:16}"
HOST_PORT="${STORJ_SIM_PG_PORT:-5433}"
PGUSER="${STORJ_SIM_PG_USER:-storj}"
PGPASSWORD="${STORJ_SIM_PG_PASSWORD:-storj}"
PGDB="${STORJ_SIM_PG_DB:-master}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [up|down|status]

  up      Start Postgres (default). Creates ${NAME} if missing.
  down    Stop ${NAME} (does not delete it).
  status  Print engine, container state, and pg_isready.

Env: CONTAINER_ENGINE=docker|container
     STORJ_SIM_PG_NAME / STORJ_SIM_PG_IMAGE / STORJ_SIM_PG_PORT
     STORJ_SIM_PG_USER / STORJ_SIM_PG_PASSWORD / STORJ_SIM_PG_DB
EOF
}

detect_engine() {
  if [[ -n "${CONTAINER_ENGINE:-}" && "${CONTAINER_ENGINE}" != "none" ]]; then
    printf '%s\n' "${CONTAINER_ENGINE}"
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if command -v container >/dev/null 2>&1; then
      echo container
    elif command -v docker >/dev/null 2>&1; then
      echo docker
    else
      echo none
    fi
  else
    if command -v docker >/dev/null 2>&1; then
      echo docker
    elif command -v container >/dev/null 2>&1; then
      echo container
    else
      echo none
    fi
  fi
}

ensure_engine() {
  ENGINE="$(detect_engine)"
  if [[ "${ENGINE}" == "none" ]]; then
    echo "No container engine found. Install Docker or Apple Container, or set CONTAINER_ENGINE." >&2
    exit 1
  fi
  if [[ "${ENGINE}" != "docker" && "${ENGINE}" != "container" ]]; then
    echo "CONTAINER_ENGINE must be 'docker' or 'container' (got '${ENGINE}')" >&2
    exit 1
  fi
}

# Apple Container needs its VM/services running before run/exec.
ensure_container_system() {
  ensure_engine
  if [[ "${ENGINE}" != "container" ]]; then
    return
  fi
  if ! container system status >/dev/null 2>&1; then
    echo "Starting Apple Container services..."
    container system start --enable-kernel-install
  fi
}

engine() {
  ensure_engine
  "${ENGINE}" "$@"
}

container_exists() {
  if [[ "${ENGINE}" == "docker" ]]; then
    docker inspect "${NAME}" >/dev/null 2>&1
  else
    container inspect "${NAME}" >/dev/null 2>&1
  fi
}

container_running() {
  if [[ "${ENGINE}" == "docker" ]]; then
    [[ "$(docker inspect -f '{{.State.Running}}' "${NAME}" 2>/dev/null || true)" == "true" ]]
  else
    container list -q 2>/dev/null | grep -qx "${NAME}"
  fi
}

pg_ready() {
  engine exec "${NAME}" pg_isready -U "${PGUSER}" -d "${PGDB}" >/dev/null 2>&1
}

wait_ready() {
  echo "Waiting for PostgreSQL in ${NAME}..."
  local i=0
  until pg_ready; do
    i=$((i + 1))
    if [[ "${i}" -gt 60 ]]; then
      echo "PostgreSQL not ready after 60s. Logs:" >&2
      engine logs "${NAME}" 2>&1 | tail -40 >&2
      exit 1
    fi
    sleep 1
  done
  echo "PostgreSQL is ready on localhost:${HOST_PORT} (${ENGINE})."
}

cmd_up() {
  ensure_container_system
  if container_running; then
    echo "${NAME} is already running (${ENGINE})."
  elif container_exists; then
    echo "Starting ${NAME} (${ENGINE})..."
    engine start "${NAME}" >/dev/null
  else
    echo "Creating ${NAME} from ${IMAGE} (${ENGINE})..."
    engine run -d --name "${NAME}" \
      -e POSTGRES_USER="${PGUSER}" \
      -e POSTGRES_PASSWORD="${PGPASSWORD}" \
      -e POSTGRES_DB="${PGDB}" \
      -p "${HOST_PORT}:5432" \
      "${IMAGE}" >/dev/null
  fi
  wait_ready
}

cmd_down() {
  ensure_engine
  if container_running; then
    engine stop "${NAME}" >/dev/null
    echo "Stopped ${NAME} (${ENGINE})."
  else
    echo "${NAME} is not running (${ENGINE})."
  fi
}

cmd_status() {
  ensure_engine
  echo "engine:    ${ENGINE}"
  if ! container_exists; then
    echo "container: missing (${NAME})"
    exit 1
  fi
  if container_running; then
    echo "container: running (${NAME})"
    if pg_ready; then
      echo "postgres:  ready on localhost:${HOST_PORT}"
    else
      echo "postgres:  not ready"
      exit 1
    fi
  else
    echo "container: stopped (${NAME})"
    exit 1
  fi
}

case "${1:-up}" in
  -h | --help | help) usage ;;
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  *)
    echo "unknown command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
