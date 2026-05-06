#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${GMSSH_BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${GMSSH_P1_MATRIX_OUT_DIR:-${BUILD_DIR}/p1-matrix/$(date +%Y%m%d-%H%M%S)}"

MODERN_SSH="${GMSSH_MODERN_SSH:-${ROOT_DIR}/build/bin/ssh}"
MODERN_SFTP="${GMSSH_MODERN_SFTP:-${ROOT_DIR}/build/bin/sftp}"
LEGACY_SSH="${GMSSH_LEGACY_SSH:-${ROOT_DIR}/build/stage/bin/ssh}"
LEGACY_SFTP="${GMSSH_LEGACY_SFTP:-${ROOT_DIR}/build/stage/bin/sftp}"

PROFILES_PATH="${GMSSH_PROFILES_PATH:-${HOME}/Library/Preferences/internal/gmssh-client/profiles.json}"
CREDENTIALS_PATH="${GMSSH_CREDENTIALS_PATH:-${HOME}/Library/Preferences/internal/gmssh-client/credentials.json}"
# Keep matrix known_hosts on an ASCII path by default.
# Some OpenSSH builds in GM environments mis-handle non-ASCII UserKnownHostsFile paths.
KNOWN_HOSTS_PATH="${GMSSH_MATRIX_KNOWN_HOSTS:-/tmp/gmssh-matrix-known_hosts-$(date +%Y%m%d-%H%M%S)}"
REPORT_PATH="${OUT_DIR}/p1-matrix-report.json"

mkdir -p "${OUT_DIR}"

preflight_targets_path="${OUT_DIR}/preflight-targets.tsv"

if [[ "${GMSSH_SKIP_CONNECTIVITY_PREFLIGHT:-0}" != "1" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 - "${PROFILES_PATH}" >"${preflight_targets_path}" <<'PY'
import json
import sys
from pathlib import Path

profiles_path = Path(sys.argv[1])
profiles = json.loads(profiles_path.read_text())

def profile_host(name):
    for profile in profiles:
        if profile.get("name") == name:
            host = str(profile.get("host", "")).strip()
            if not host:
                raise SystemExit(f"profile {name!r} has no host")
            return host
    raise SystemExit(f"profile {name!r} not found in {profiles_path}")

kylin_host = profile_host("麒麟 V10 SP3")
openeuler_host = profile_host("open Euler")

print(f"麒麟 V10 SP3 standard/GM\t{kylin_host}\t22")
print(f"openEuler pure-GM debug\t{openeuler_host}\t2222")
print(f"openEuler standard SSH\t{openeuler_host}\t22")
PY

    preflight_failed=0
    while IFS=$'\t' read -r label host port; do
      [[ -z "${label}" ]] && continue
      if nc -z -G 3 "${host}" "${port}" >/dev/null 2>&1 ||
         nc -z -w 3 "${host}" "${port}" >/dev/null 2>&1; then
        printf '[预检] %s %s:%s 可达\n' "${label}" "${host}" "${port}"
      else
        printf '[预检] %s %s:%s 不可达\n' "${label}" "${host}" "${port}" >&2
        preflight_failed=1
      fi
    done <"${preflight_targets_path}"

    if [[ "${preflight_failed}" -ne 0 ]]; then
      cat >&2 <<EOF
[预检] P1 矩阵未执行：测试主机/端口不可达。
[预检] 请先确认 VPN/测试网络已连通，以及 openEuler 纯国密调试 sshd 已在 2222 端口启动。
[预检] 如需跳过连通性预检，可设置 GMSSH_SKIP_CONNECTIVITY_PREFLIGHT=1。
EOF
      exit 3
    fi
  else
    echo "[预检] 未找到 python3，跳过 profiles.json 连通性预检。" >&2
  fi
fi

cmake --build "${BUILD_DIR}" --target gmssh_p1_matrix -j

"${BUILD_DIR}/gmssh_p1_matrix" \
  --profiles "${PROFILES_PATH}" \
  --credentials "${CREDENTIALS_PATH}" \
  --known-hosts "${KNOWN_HOSTS_PATH}" \
  --modern-ssh "${MODERN_SSH}" \
  --modern-sftp "${MODERN_SFTP}" \
  --legacy-ssh "${LEGACY_SSH}" \
  --legacy-sftp "${LEGACY_SFTP}" \
  --output "${REPORT_PATH}"

if [[ -f "${KNOWN_HOSTS_PATH}" ]]; then
  cp -f "${KNOWN_HOSTS_PATH}" "${OUT_DIR}/known_hosts.snapshot"
fi

echo "report=${REPORT_PATH}"
