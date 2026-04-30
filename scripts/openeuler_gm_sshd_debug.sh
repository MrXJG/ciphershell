#!/usr/bin/env bash
set -euo pipefail

PORT="${GMSSHD_DEBUG_PORT:-2222}"
BIND_ADDR="${GMSSHD_DEBUG_BIND_ADDR:-0.0.0.0}"
ROOT_DIR="${GMSSHD_DEBUG_ROOT:-/etc/ssh/gm-debug}"
HOSTKEY="${ROOT_DIR}/ssh_host_sm2_key"
CONFIG="${ROOT_DIR}/sshd_config"
PID_FILE="${GMSSHD_DEBUG_PID_FILE:-/run/gmsshd-debug.pid}"
LOG_FILE="${GMSSHD_DEBUG_LOG_FILE:-/var/log/gmsshd-debug.log}"
SSHD="${GMSSHD_SSHD:-/usr/sbin/sshd}"
SSH="${GMSSHD_SSH:-/usr/bin/ssh}"
SSH_KEYGEN="${GMSSHD_SSH_KEYGEN:-/usr/bin/ssh-keygen}"
SERVICE_NAME="${GMSSHD_DEBUG_SERVICE:-gmsshd-debug.service}"
UNIT_FILE="${GMSSHD_DEBUG_UNIT_FILE:-/etc/systemd/system/${SERVICE_NAME}}"
KEX_ALGORITHMS="${GMSSHD_KEX_ALGORITHMS:-sm2-sm3}"
HOSTKEY_ALGORITHMS="${GMSSHD_HOSTKEY_ALGORITHMS:-sm2,sm2-cert}"
PUBKEY_ALGORITHMS="${GMSSHD_PUBKEY_ALGORITHMS:-sm2,sm2-cert}"
CIPHERS="${GMSSHD_CIPHERS:-sm4-ctr}"
MACS="${GMSSHD_MACS:-hmac-sm3}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root_for_write() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "start/stop/status must run as root"
  fi
}

require_binary() {
  local path="$1"
  [[ -x "${path}" ]] || die "missing executable: ${path}"
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required for service management"
}

check_capability() {
  require_binary "${SSH}"
  require_binary "${SSHD}"
  require_binary "${SSH_KEYGEN}"

  printf 'ssh=%s\n' "${SSH}"
  printf 'sshd=%s\n' "${SSHD}"
  printf 'ssh-keygen=%s\n' "${SSH_KEYGEN}"
  printf 'ssh_version='
  "${SSH}" -V 2>&1 || true

  printf 'kex_sm2='
  "${SSH}" -Q kex | grep -E '^(sm2-sm3|ecgm-sm2-sm3)$' | tr '\n' ',' | sed 's/,$//' || true
  printf '\n'

  printf 'key_sm2='
  "${SSH}" -Q key | grep -E '^sm2(-cert)?$' | tr '\n' ',' | sed 's/,$//' || true
  printf '\n'

  printf 'cipher_sm4='
  "${SSH}" -Q cipher | grep -E '^sm4-ctr$' | tr '\n' ',' | sed 's/,$//' || true
  printf '\n'

  printf 'mac_sm3='
  "${SSH}" -Q mac | grep -E '^hmac-sm3$' | tr '\n' ',' | sed 's/,$//' || true
  printf '\n'

  printf 'effective_default_algorithms_begin\n'
  "${SSHD}" -T 2>/dev/null | grep -E \
    '^(kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|ciphers|macs) ' || true
  printf 'effective_default_algorithms_end\n'
}

write_config() {
  mkdir -p "${ROOT_DIR}"
  chmod 700 "${ROOT_DIR}"

  if [[ ! -f "${HOSTKEY}" ]]; then
    "${SSH_KEYGEN}" -q -t sm2 -N '' -f "${HOSTKEY}" || \
      die "failed to generate SM2 host key; check whether server OpenSSH supports 'ssh-keygen -t sm2'"
  fi

  cat > "${CONFIG}" <<EOF
Port ${PORT}
ListenAddress ${BIND_ADDR}
Protocol 2
PidFile ${PID_FILE}
LogLevel DEBUG3

HostKey ${HOSTKEY}
KexAlgorithms ${KEX_ALGORITHMS}
HostKeyAlgorithms ${HOSTKEY_ALGORITHMS}
PubkeyAcceptedAlgorithms ${PUBKEY_ALGORITHMS}
Ciphers ${CIPHERS}
MACs ${MACS}

PasswordAuthentication yes
KbdInteractiveAuthentication yes
PermitRootLogin yes
UsePAM yes

Subsystem sftp internal-sftp
EOF

  chmod 600 "${CONFIG}" "${HOSTKEY}"
  [[ ! -f "${HOSTKEY}.pub" ]] || chmod 644 "${HOSTKEY}.pub"
}

validate_config() {
  printf 'validate_config=%s\n' "${CONFIG}"
  "${SSHD}" -t -f "${CONFIG}" -E "${LOG_FILE}"
  printf 'validate_config_ok=1\n'
  printf 'effective_debug_algorithms_begin\n'
  "${SSHD}" -T -f "${CONFIG}" | grep -E '^(port|listenaddress|hostkey |kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|ciphers|macs|passwordauthentication|permitrootlogin) '
  printf 'effective_debug_algorithms_end\n'
}

write_systemd_unit() {
  cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=GMSSH isolated pure-GM sshd test service on port ${PORT}
Documentation=man:sshd(8)
After=network.target sshd.service ssh.service
ConditionPathExists=${CONFIG}

[Service]
Type=simple
ExecStartPre=${SSHD} -t -f ${CONFIG} -E ${LOG_FILE}
ExecStart=${SSHD} -D -f ${CONFIG} -E ${LOG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2s
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "${UNIT_FILE}"
}

port_is_listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn | awk -v port=":${PORT}" '$4 ~ port {found=1} END {exit found ? 0 : 1}'
    return
  fi

  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v port=":${PORT}" '$4 ~ port {found=1} END {exit found ? 0 : 1}'
    return
  fi

  return 2
}

stop_pid_file_listener() {
  if [[ ! -f "${PID_FILE}" ]]; then
    return
  fi

  local pid
  pid="$(cat "${PID_FILE}")"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
  fi
  rm -f "${PID_FILE}"
}

print_client_probe_command() {
  local host
  host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "${host}" ]] || host="<openEuler-host>"

  cat <<EOF
client_probe_command:
  GMSSH_OPENEULER_HOST=${host} GMSSH_OPENEULER_GM_PORT=${PORT} scripts/gm_handshake_regression.sh
direct_probe_command:
  build/bin/ssh -vvv -p ${PORT} -o KexAlgorithms=${KEX_ALGORITHMS} -o HostKeyAlgorithms=${HOSTKEY_ALGORITHMS} -o PubkeyAcceptedAlgorithms=${PUBKEY_ALGORITHMS} -o Ciphers=${CIPHERS} -o MACs=${MACS} root@${host}
EOF
}

start_debug_sshd() {
  require_root_for_write
  check_capability
  write_config
  validate_config

  if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    die "debug sshd already running: pid $(cat "${PID_FILE}")"
  fi

  : > "${LOG_FILE}"
  "${SSHD}" -D -f "${CONFIG}" -E "${LOG_FILE}" </dev/null >/dev/null 2>&1 &
  local pid=$!
  printf '%s\n' "${pid}" > "${PID_FILE}"
  sleep 1

  if ! kill -0 "${pid}" 2>/dev/null; then
    tail -n 80 "${LOG_FILE}" >&2 || true
    die "debug sshd failed to start"
  fi

  if port_is_listening; then
    printf 'port_listening=1\n'
  else
    printf 'port_listening=unknown_or_0\n'
  fi

  printf 'debug_sshd_started=1\n'
  printf 'pid=%s\n' "${pid}"
  printf 'port=%s\n' "${PORT}"
  printf 'config=%s\n' "${CONFIG}"
  printf 'log=%s\n' "${LOG_FILE}"
  print_client_probe_command
}

stop_debug_sshd() {
  require_root_for_write
  if command -v systemctl >/dev/null 2>&1 && [[ -f "${UNIT_FILE}" ]]; then
    systemctl stop "${SERVICE_NAME}" || true
  fi
  stop_pid_file_listener
  printf 'debug_sshd_stopped=1\n'
}

print_service_status() {
  if command -v systemctl >/dev/null 2>&1 && [[ -f "${UNIT_FILE}" ]]; then
    printf 'service=%s\n' "${SERVICE_NAME}"
    printf 'service_active='
    systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true
    printf 'service_enabled='
    systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || true
    printf 'service_main_pid='
    systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || true
  else
    printf 'service_installed=0\n'
  fi
}

status_debug_sshd() {
  require_root_for_write
  print_service_status
  if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    printf 'debug_sshd_running=1\n'
    printf 'pid=%s\n' "$(cat "${PID_FILE}")"
  else
    printf 'debug_sshd_running=0\n'
  fi
  [[ ! -f "${LOG_FILE}" ]] || tail -n 40 "${LOG_FILE}"
}

doctor_debug_sshd() {
  require_root_for_write
  check_capability
  write_config
  validate_config

  printf 'doctor_pid_file=%s\n' "${PID_FILE}"
  if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    printf 'debug_sshd_running=1\n'
    printf 'pid=%s\n' "$(cat "${PID_FILE}")"
  else
    printf 'debug_sshd_running=0\n'
  fi

  if port_is_listening; then
    printf 'port_listening=1\n'
  else
    printf 'port_listening=0\n'
  fi

  print_client_probe_command
  [[ ! -f "${LOG_FILE}" ]] || {
    printf 'log_tail_begin\n'
    tail -n 80 "${LOG_FILE}" || true
    printf 'log_tail_end\n'
  }
}

install_service() {
  require_root_for_write
  require_systemd
  check_capability
  write_config
  validate_config
  write_systemd_unit

  stop_pid_file_listener
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
  sleep 1

  print_service_status
  if port_is_listening; then
    printf 'port_listening=1\n'
  else
    printf 'port_listening=0\n'
  fi
  printf 'unit=%s\n' "${UNIT_FILE}"
  printf 'config=%s\n' "${CONFIG}"
  printf 'log=%s\n' "${LOG_FILE}"
  print_client_probe_command
}

uninstall_service() {
  require_root_for_write
  require_systemd
  if [[ -f "${UNIT_FILE}" ]]; then
    systemctl disable --now "${SERVICE_NAME}" || true
    rm -f "${UNIT_FILE}"
    systemctl daemon-reload
  fi
  stop_pid_file_listener
  printf 'service_uninstalled=1\n'
}

case "${1:-check}" in
  check)
    check_capability
    ;;
  config)
    require_root_for_write
    check_capability
    write_config
    validate_config
    ;;
  start)
    start_debug_sshd
    ;;
  stop)
    stop_debug_sshd
    ;;
  status)
    status_debug_sshd
    ;;
  doctor)
    doctor_debug_sshd
    ;;
  install-service)
    install_service
    ;;
  uninstall-service)
    uninstall_service
    ;;
  *)
    die "usage: $0 [check|config|start|stop|status|doctor|install-service|uninstall-service]"
    ;;
esac
