#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${GMSSH_BUILD_DIR:-${ROOT_DIR}/build}"
BUILD_TYPE="${GMSSH_BUILD_TYPE:-Release}"
REPORT_DIR="${GMSSH_PACKAGE_REPORT_DIR:-${BUILD_DIR}/package-verification/$(date +%Y%m%d-%H%M%S)}"
APP_PATH="${GMSSH_APP_PATH:-${BUILD_DIR}/gmssh_client.app}"
APP_EXECUTABLE="${APP_PATH}/Contents/MacOS/gmssh_client"
APP_ENGINE_DIR="${APP_PATH}/Contents/MacOS/bin"
REPORT_PATH="${REPORT_DIR}/package-report.json"
P1_REPORT_PATH="${REPORT_DIR}/p1-matrix-report.json"
PACKAGE_FILE_NAME="${GMSSH_PACKAGE_FILE_NAME:-gmssh-client-0.1.0-Darwin}"
DMG_PATH="${BUILD_DIR}/${PACKAGE_FILE_NAME}.dmg"
MACDEPLOYQT_STATUS="skipped"
DMG_STATUS="skipped"
STAGED_APP_PATH=""
CODESIGN_STATUS="skipped"
P1_STATUS="skipped"
PATH_LEAK_STATUS="pass"
BUNDLE_LINK_STATUS="pass"
MACDEPLOYQT_LIBPATH_ARGS=()

mkdir -p "${REPORT_DIR}"
BUILD_JOBS="${GMSSH_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

append_brew_libpath() {
  local formula="$1"
  local prefix=""
  if command -v brew >/dev/null 2>&1; then
    prefix="$(brew --prefix "${formula}" 2>/dev/null || true)"
  fi
  if [[ -z "${prefix}" && -d "/opt/homebrew/opt/${formula}/lib" ]]; then
    prefix="/opt/homebrew/opt/${formula}"
  fi
  if [[ -n "${prefix}" && -d "${prefix}/lib" ]]; then
    MACDEPLOYQT_LIBPATH_ARGS+=("-libpath=${prefix}/lib")
  fi
}

sign_and_verify_app() {
  local app="$1"
  local log="$2"
  codesign --force --deep --sign - --timestamp=none "${app}" >"${log}" 2>&1
  codesign --verify --deep --strict --verbose=4 "${app}" >>"${log}" 2>&1
}

repair_qt_plugin_bundle_links() {
  local app="$1"
  local frameworks_dir="${app}/Contents/Frameworks"
  local engine_dir="${app}/Contents/MacOS/bin"
  local plugins_dir="${app}/Contents/PlugIns"
  local qtsvg_src="/opt/homebrew/opt/qtsvg/lib/QtSvg.framework"
  local qtsvg_dst="${frameworks_dir}/QtSvg.framework"

  rm -f \
    "${plugins_dir}/imageformats/libqpdf.dylib" \
    "${plugins_dir}/platforminputcontexts/libqtvirtualkeyboardplugin.dylib"

  if [[ -d "${qtsvg_src}" && -f "${plugins_dir}/iconengines/libqsvgicon.dylib" ]]; then
    rm -rf "${qtsvg_dst}"
    ditto "${qtsvg_src}" "${qtsvg_dst}"
    install_name_tool \
      -id "@executable_path/../Frameworks/QtSvg.framework/Versions/A/QtSvg" \
      "${qtsvg_dst}/Versions/A/QtSvg"
    install_name_tool \
      -change "/opt/homebrew/opt/qtbase/lib/QtGui.framework/Versions/A/QtGui" \
      "@executable_path/../Frameworks/QtGui.framework/Versions/A/QtGui" \
      -change "/opt/homebrew/opt/qtbase/lib/QtCore.framework/Versions/A/QtCore" \
      "@executable_path/../Frameworks/QtCore.framework/Versions/A/QtCore" \
      "${qtsvg_dst}/Versions/A/QtSvg"
    install_name_tool \
      -change "@rpath/QtSvg.framework/Versions/A/QtSvg" \
      "@executable_path/../Frameworks/QtSvg.framework/Versions/A/QtSvg" \
      "${plugins_dir}/iconengines/libqsvgicon.dylib"
  fi

  while IFS= read -r engine_binary; do
    install_name_tool \
      -change "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib" \
      "@executable_path/../../Frameworks/libcrypto.3.dylib" \
      -change "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib" \
      "@executable_path/../../Frameworks/libssl.3.dylib" \
      "${engine_binary}" 2>/dev/null || true
  done < <(find "${engine_dir}" -type f -perm -111 -print 2>/dev/null)
}

verify_bundle_links() {
  local app="$1"
  local report_dir="$2"
  local issues="${report_dir}/bundle-link-issues.txt"
  : >"${issues}"

  while IFS= read -r binary; do
    while IFS= read -r dep; do
      dep="${dep%% (*}"
      dep="${dep#"${dep%%[![:space:]]*}"}"
      [[ -z "${dep}" ]] && continue

      if [[ "${dep}" == /opt/homebrew/* || "${dep}" == /usr/local/* || "${dep}" == "${ROOT_DIR}"* ]]; then
        BUNDLE_LINK_STATUS="fail"
        printf '%s -> %s\n' "${binary}" "${dep}" >>"${issues}"
        continue
      fi

      if [[ "${dep}" == @rpath/*.framework/Versions/A/* ]]; then
        local framework="${dep#@rpath/}"
        framework="${framework%%/Versions/A/*}.framework"
        if [[ ! -d "${app}/Contents/Frameworks/${framework}" ]]; then
          BUNDLE_LINK_STATUS="fail"
          printf '%s -> unresolved %s\n' "${binary}" "${dep}" >>"${issues}"
        fi
      elif [[ "${dep}" == @rpath/*.dylib ]]; then
        local dylib="${dep#@rpath/}"
        if [[ ! -f "${app}/Contents/Frameworks/${dylib}" && \
              ! -f "${app}/Contents/MacOS/${dylib}" && \
              ! -f "${app}/Contents/lib/${dylib}" ]]; then
          BUNDLE_LINK_STATUS="fail"
          printf '%s -> unresolved %s\n' "${binary}" "${dep}" >>"${issues}"
        fi
      fi
    done < <(otool -L "${binary}" 2>/dev/null | tail -n +2)
  done < <(find "${app}/Contents" -type f -perm -111 -print)
}

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
rm -rf "${APP_PATH}"
cmake --build "${BUILD_DIR}" --clean-first --parallel "${BUILD_JOBS}"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "[打包] 未找到 App bundle: ${APP_PATH}" >&2
  exit 2
fi

if [[ ! -x "${APP_EXECUTABLE}" ]]; then
  echo "[打包] App 主程序不可执行: ${APP_EXECUTABLE}" >&2
  exit 2
fi
if [[ ! -f "${APP_PATH}/Contents/Info.plist" ]]; then
  echo "[打包] App Info.plist 缺失: ${APP_PATH}/Contents/Info.plist" >&2
  exit 2
fi

append_brew_libpath qtsvg
append_brew_libpath qtwebengine
append_brew_libpath qtvirtualkeyboard
append_brew_libpath webp
append_brew_libpath brotli

if command -v macdeployqt >/dev/null 2>&1; then
  macdeployqt_log="${REPORT_DIR}/macdeployqt.log"
  macdeployqt "${APP_PATH}" -always-overwrite -no-codesign \
    "${MACDEPLOYQT_LIBPATH_ARGS[@]}" >"${macdeployqt_log}" 2>&1
  if grep -q '^ERROR:' "${macdeployqt_log}"; then
    MACDEPLOYQT_STATUS="repaired"
  else
    MACDEPLOYQT_STATUS="pass"
  fi
else
  MACDEPLOYQT_STATUS="not_found"
fi

if [[ ! -x "${APP_EXECUTABLE}" || ! -f "${APP_PATH}/Contents/Info.plist" ]]; then
  echo "[打包] macdeployqt 后 App bundle 结构无效: ${APP_PATH}" >&2
  exit 2
fi

repair_qt_plugin_bundle_links "${APP_PATH}"
verify_bundle_links "${APP_PATH}" "${REPORT_DIR}"
if [[ "${BUNDLE_LINK_STATUS}" != "pass" ]]; then
  echo "[打包] App bundle 仍存在外部或未解析动态库依赖，详情见 ${REPORT_DIR}/bundle-link-issues.txt" >&2
  exit 2
fi

codesign_log="${REPORT_DIR}/codesign-build-app.log"
sign_and_verify_app "${APP_PATH}" "${codesign_log}"
CODESIGN_STATUS="pass"

required_binaries=(
  "${APP_ENGINE_DIR}/ssh"
  "${APP_ENGINE_DIR}/sftp"
  "${APP_ENGINE_DIR}/ssh-legacy-ecgm"
  "${APP_ENGINE_DIR}/sftp-legacy-ecgm"
)

for binary in "${required_binaries[@]}"; do
  if [[ ! -x "${binary}" ]]; then
    echo "[打包] 包内引擎缺失或不可执行: ${binary}" >&2
    exit 2
  fi
done

"${APP_ENGINE_DIR}/ssh" -Q kex >"${REPORT_DIR}/modern-kex.txt"
"${APP_ENGINE_DIR}/ssh" -Q key >"${REPORT_DIR}/modern-key.txt"
"${APP_ENGINE_DIR}/ssh" -Q cipher >"${REPORT_DIR}/modern-cipher.txt"
"${APP_ENGINE_DIR}/ssh" -Q mac >"${REPORT_DIR}/modern-mac.txt"
"${APP_ENGINE_DIR}/ssh-legacy-ecgm" -Q kex >"${REPORT_DIR}/legacy-kex.txt"
"${APP_ENGINE_DIR}/ssh-legacy-ecgm" -Q key >"${REPORT_DIR}/legacy-key.txt"
"${APP_ENGINE_DIR}/ssh-legacy-ecgm" -Q cipher >"${REPORT_DIR}/legacy-cipher.txt"
"${APP_ENGINE_DIR}/ssh-legacy-ecgm" -Q mac >"${REPORT_DIR}/legacy-mac.txt"

leak_file="${REPORT_DIR}/developer-path-leaks.txt"
: >"${leak_file}"
while IFS= read -r executable; do
  if strings "${executable}" | grep -F "${ROOT_DIR}" >>"${leak_file}"; then
    PATH_LEAK_STATUS="fail"
  fi
done < <(find "${APP_PATH}/Contents/MacOS" -type f -perm -111 -print)

if [[ "${PATH_LEAK_STATUS}" != "pass" ]]; then
  echo "[打包] 包内可执行文件包含开发目录路径，详情见 ${leak_file}" >&2
  exit 2
fi

if [[ "${GMSSH_RUN_PACKAGE_P1:-1}" == "1" ]]; then
  if [[ -f "${HOME}/Library/Preferences/internal/gmssh-client/profiles.json" && \
        -f "${HOME}/Library/Preferences/internal/gmssh-client/credentials.json" ]]; then
    GMSSH_MODERN_SSH="${APP_ENGINE_DIR}/ssh" \
    GMSSH_MODERN_SFTP="${APP_ENGINE_DIR}/sftp" \
    GMSSH_LEGACY_SSH="${APP_ENGINE_DIR}/ssh-legacy-ecgm" \
    GMSSH_LEGACY_SFTP="${APP_ENGINE_DIR}/sftp-legacy-ecgm" \
    GMSSH_P1_MATRIX_OUT_DIR="${REPORT_DIR}" \
      "${ROOT_DIR}/scripts/p1_matrix_regression.sh"
    P1_STATUS="pass"
  else
    P1_STATUS="missing_profiles_or_credentials"
  fi
fi

if [[ "${GMSSH_CREATE_DMG:-1}" == "1" ]]; then
  dmg_root="${REPORT_DIR}/dmg-root"
  rm -rf "${dmg_root}"
  mkdir -p "${dmg_root}"
  STAGED_APP_PATH="${dmg_root}/gmssh_client.app"
  ditto "${APP_PATH}" "${STAGED_APP_PATH}"
  ln -s /Applications "${dmg_root}/Applications"
  sign_and_verify_app "${STAGED_APP_PATH}" "${REPORT_DIR}/codesign-staged-app.log"
  hdiutil create \
    -volname "GMSSH Client" \
    -srcfolder "${dmg_root}" \
    -ov \
    -format UDZO \
    "${DMG_PATH}" >"${REPORT_DIR}/hdiutil-create.log" 2>&1
  hdiutil imageinfo "${DMG_PATH}" >"${REPORT_DIR}/hdiutil-imageinfo.log" 2>&1
  DMG_STATUS="pass"
fi

python3 - "${REPORT_PATH}" "${ROOT_DIR}" "${APP_PATH}" "${APP_EXECUTABLE}" "${APP_ENGINE_DIR}" "${REPORT_DIR}" "${DMG_PATH}" "${STAGED_APP_PATH}" "${MACDEPLOYQT_STATUS}" "${CODESIGN_STATUS}" "${DMG_STATUS}" "${P1_STATUS}" "${BUNDLE_LINK_STATUS}" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    report_path,
    root_dir,
    app_path,
    app_executable,
    app_engine_dir,
    report_dir,
    dmg_path,
    staged_app_path,
    macdeployqt_status,
    codesign_status,
    dmg_status,
    p1_status,
    bundle_link_status,
) = sys.argv[1:]

report_dir_p = Path(report_dir)
engine_dir = Path(app_engine_dir)

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def lines(name: str) -> list[str]:
    path = report_dir_p / name
    return path.read_text().splitlines() if path.exists() else []

def has(name: str, value: str) -> bool:
    return value in lines(name)

binaries = {}
for name in ['ssh', 'sftp', 'ssh-legacy-ecgm', 'sftp-legacy-ecgm']:
    path = engine_dir / name
    binaries[name] = {
        'path': str(path),
        'executable': os.access(path, os.X_OK),
        'size': path.stat().st_size if path.exists() else None,
        'sha256': sha256(path) if path.exists() else None,
    }

report = {
    'verdict': 'pass',
    'root_dir': root_dir,
    'app_path': app_path,
    'app_executable': app_executable,
    'report_dir': report_dir,
    'macdeployqt': macdeployqt_status,
    'codesign': codesign_status,
    'bundle_links': bundle_link_status,
    'dmg': dmg_status,
    'dmg_path': dmg_path,
    'staged_app_path': staged_app_path,
    'p1_matrix': p1_status,
    'binaries': binaries,
    'algorithm_checks': {
        'modern_ecgm_sm2_sm3': has('modern-kex.txt', 'ecgm-sm2-sm3'),
        'modern_sm2_sm3': has('modern-kex.txt', 'sm2-sm3'),
        'modern_sm2_key': has('modern-key.txt', 'sm2'),
        'modern_sm4_ctr': has('modern-cipher.txt', 'sm4-ctr'),
        'modern_hmac_sm3': has('modern-mac.txt', 'hmac-sm3'),
        'legacy_ecgm_sm2_sm3': has('legacy-kex.txt', 'ecgm-sm2-sm3'),
        'legacy_sm2_key': has('legacy-key.txt', 'sm2'),
        'legacy_sm4_ctr': has('legacy-cipher.txt', 'sm4-ctr'),
        'legacy_hmac_sm3': has('legacy-mac.txt', 'hmac-sm3'),
    },
    'developer_path_leak': 'pass',
}

failed = [k for k, v in report['algorithm_checks'].items() if not v]
if failed:
    report['verdict'] = 'fail'
    report['failed_algorithm_checks'] = failed

Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
if report['verdict'] != 'pass':
    raise SystemExit(2)
PY

echo "report=${REPORT_PATH}"
if [[ -n "${DMG_PATH}" ]]; then
  echo "dmg=${DMG_PATH}"
fi
