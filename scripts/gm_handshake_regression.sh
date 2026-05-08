#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${GMSSH_BUILD_DIR:-${ROOT_DIR}/build}"
APP_BIN_DIR="${BUILD_DIR}/CipherShell.app/Contents/MacOS/bin"

resolve_engine_path() {
  local fallback="$1"
  shift
  for candidate in "$@"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  printf '%s' "${fallback}"
}

MODERN_SSH="${GMSSH_MODERN_SSH:-$(resolve_engine_path "${ROOT_DIR}/bin/ssh" "${ROOT_DIR}/bin/ssh" "${APP_BIN_DIR}/ssh" "${BUILD_DIR}/bin/ssh")}"
LEGACY_SSH="${GMSSH_LEGACY_SSH:-$(resolve_engine_path "${ROOT_DIR}/bin/ssh-legacy-ecgm" "${ROOT_DIR}/bin/ssh-legacy-ecgm" "${APP_BIN_DIR}/ssh-legacy-ecgm" "${BUILD_DIR}/bin/ssh-legacy-ecgm")}"
KYLIN_HOST="${GMSSH_KYLIN_HOST:-10.0.13.1}"
OPENEULER_HOST="${GMSSH_OPENEULER_HOST:-10.0.13.2}"
OPENEULER_GM_PORT="${GMSSH_OPENEULER_GM_PORT:-2222}"
OUT_DIR="${GMSSH_REGRESSION_OUT_DIR:-${ROOT_DIR}/build/regression/$(date +%Y%m%d-%H%M%S)}"

mkdir -p "${OUT_DIR}"

gm_args=(
  -o KexAlgorithms=ecgm-sm2-sm3,sm2-sm3
  -o HostKeyAlgorithms=sm2,sm2-cert
  -o PubkeyAcceptedAlgorithms=sm2,sm2-cert
  -o Ciphers=sm4-ctr
  -o MACs=hmac-sm3
)

common_args=(
  -o BatchMode=yes
  -o PreferredAuthentications=none
  -o NumberOfPasswordPrompts=0
  -o ConnectTimeout=8
  -o StrictHostKeyChecking=accept-new
)

summarize_log() {
  local log_file="$1"

  grep -E \
    'Connection established|kex: algorithm|kex: host key algorithm|ciphers ctos|MACs ctos|host signature verify|message authentication code incorrect|verify KEX signature|Unable to negotiate|Their offer|Connection refused|Operation timed out|Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED' \
    "${log_file}" || true

  grep -Eq 'AUTH_FAILED|Permission denied' "${log_file}" && printf 'auth_boundary=1\n' || printf 'auth_boundary=0\n'
  grep -q 'message authentication code incorrect' "${log_file}" && printf 'mac_error=1\n' || printf 'mac_error=0\n'
  grep -q 'verify KEX signature' "${log_file}" && printf 'verify_kex_error=1\n' || printf 'verify_kex_error=0\n'
}

run_probe() {
  local label="$1"
  local engine="$2"
  local host="$3"
  local port="$4"
  local mode="$5"
  local log_file="${OUT_DIR}/${label}.log"
  local known_hosts="${OUT_DIR}/${label}.known_hosts"
  local rc

  printf '\n== %s ==\n' "${label}"

  if [[ ! -x "${engine}" ]]; then
    printf 'engine_missing=%s\n' "${engine}"
    return
  fi

  if [[ "${mode}" == "gm" ]]; then
    GMSSH_ECGM_HOSTSIG_BYPASS=1 "${engine}" \
      -E "${log_file}" -vvv -p "${port}" \
      "${gm_args[@]}" "${common_args[@]}" \
      -o "UserKnownHostsFile=${known_hosts}" \
      "root@${host}" exit >/dev/null 2>&1
  else
    "${engine}" \
      -E "${log_file}" -vvv -p "${port}" \
      "${common_args[@]}" \
      -o "UserKnownHostsFile=${known_hosts}" \
      "root@${host}" exit >/dev/null 2>&1
  fi

  rc=$?
  printf 'exit=%s\n' "${rc}"
  summarize_log "${log_file}"
}

run_probe "kylin-modern-gm" "${MODERN_SSH}" "${KYLIN_HOST}" 22 gm
run_probe "kylin-legacy-gm" "${LEGACY_SSH}" "${KYLIN_HOST}" 22 gm
run_probe "kylin-modern-standard" "${MODERN_SSH}" "${KYLIN_HOST}" 22 standard
run_probe "openeuler22-modern-gm" "${MODERN_SSH}" "${OPENEULER_HOST}" "${OPENEULER_GM_PORT}" gm
run_probe "openeuler22-modern-standard" "${MODERN_SSH}" "${OPENEULER_HOST}" 22 standard

seen_ports=""
for port in "${OPENEULER_GM_PORT}" 2222 2224; do
  [[ "${port}" == "22" ]] && continue
  case " ${seen_ports} " in
    *" ${port} "*) continue ;;
  esac
  seen_ports="${seen_ports} ${port}"
  printf '\n== openeuler-port-%s ==\n' "${port}"
  nc -vz -G 3 "${OPENEULER_HOST}" "${port}" >/dev/null 2>&1
  printf 'tcp_open=%s\n' "$([[ $? -eq 0 ]] && printf 1 || printf 0)"
done

printf '\nlogs=%s\n' "${OUT_DIR}"
