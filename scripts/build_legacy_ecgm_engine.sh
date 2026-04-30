#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${GMSSH_LEGACY_ENGINE_SOURCE_DIR:-${ROOT_DIR}/engine/openssh-gm}"
WORK_DIR="${GMSSH_LEGACY_ENGINE_WORK_DIR:-${ROOT_DIR}/engine/build/openssh-legacy-ecgm-work}"
INSTALL_DIR="${GMSSH_LEGACY_ENGINE_INSTALL_DIR:-${ROOT_DIR}/engine/install/legacy-ecgm}"
BIN_DIR="${GMSSH_ENGINE_BIN_DIR:-${ROOT_DIR}/bin}"
BUILD_BIN_DIR="${GMSSH_ENGINE_BUILD_BIN_DIR:-${ROOT_DIR}/build-win/bin}"
EXE_SUFFIX=""
MAKE_JOBS="${GMSSH_ENGINE_BUILD_JOBS:-4}"
OPENSSL_PREFIX="${GMSSH_OPENSSL_PREFIX:-}"
CONFIGURE_EXTRA_ARGS=()

if [[ -n "${GMSSH_LEGACY_CONFIGURE_EXTRA_ARGS:-}" ]]; then
  read -r -a CONFIGURE_EXTRA_ARGS <<< "${GMSSH_LEGACY_CONFIGURE_EXTRA_ARGS}"
fi

case "$(uname -s 2>/dev/null || true)" in
  CYGWIN*|MSYS*|MINGW*) EXE_SUFFIX=".exe" ;;
esac

if [[ -z "${OPENSSL_PREFIX}" ]] && command -v brew >/dev/null 2>&1; then
  if brew --prefix openssl@3 >/dev/null 2>&1; then
    OPENSSL_PREFIX="$(brew --prefix openssl@3)"
  fi
fi

if command -v nproc >/dev/null 2>&1; then
  MAKE_JOBS="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
  MAKE_JOBS="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)"
fi

BUILD_SOURCE_DIR="${WORK_DIR}"

prepare_from_prepared_tree() {
  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}" "${INSTALL_DIR}" "${BIN_DIR}"

  tar -C "${SOURCE_DIR}" \
    --exclude='.git' \
    --exclude='*.o' \
    --exclude='*.a' \
    --exclude='*.exe' \
    --exclude='ssh' \
    --exclude='sftp' \
    -cf - . | tar -C "${WORK_DIR}" -xf -

  BUILD_SOURCE_DIR="${WORK_DIR}"
}

apply_openeuler_88_fallbacks() {
  if ! grep -q 'ssh-sm2.o' Makefile.in; then
    perl -0pi -e 's/ssh-dss\.o ssh-ecdsa\.o ssh-ecdsa-sk\.o/ssh-dss.o ssh-ecdsa.o ssh-sm2.o ssh-ecdsa-sk.o/' Makefile.in
  fi
  if ! grep -q 'kexsm2.o' Makefile.in; then
    perl -0pi -e 's/kex\.o kexdh\.o kexgex\.o kexecdh\.o kexc25519\.o/kex.o kexdh.o kexgex.o kexecdh.o kexc25519.o kexsm2.o/' Makefile.in
  fi
  if ! grep -q 'KEX_SM2_SM3' kex.h; then
    perl -0pi -e 's/(KEX_KEM_SNTRUP761X25519_SHA512,\n)/$1\tKEX_SM2_SM3,\n/' kex.h
  fi
  if ! grep -q '"sm2", "SM2"' sshkey.c; then
    perl -0pi -e 's/(# endif \/\* OPENSSL_HAS_ECC \*\/\n#endif \/\* WITH_OPENSSL \*\/)/\t{ "sm2", "SM2", NULL, KEY_SM2, NID_sm2, 0, 0 },\n\t{ "sm2-cert", "SM2-CERT", NULL, KEY_SM2_CERT, NID_sm2, 1, 0 },\n$1/' sshkey.c
  fi

  for source_file in kex.c kexecdh.c sshkey.c; do
    if grep -q 'NID_sm2' "${source_file}" && ! grep -q 'obj_mac.h' "${source_file}"; then
      perl -0pi -e 's/#include <openssl\/([^>]+)>/#include <openssl\/$1>\n#include <openssl\/obj_mac.h>/' "${source_file}"
    fi
  done
}

prepare_from_openeuler_pack() {
  local tarball
  local patch_sm
  local patch_evp

  tarball="$(find "${SOURCE_DIR}" -maxdepth 1 -type f -name 'openssh-*.tar.gz' | head -n 1 || true)"
  patch_sm="${SOURCE_DIR}/feature-add-SMx-support.patch"
  patch_evp="${SOURCE_DIR}/backport-openssh-8.0p1-openssl-evp.patch"

  if [[ -z "${tarball}" || ! -f "${patch_sm}" ]]; then
    cat >&2 <<MSG
Missing legacy EC-GM source input: ${SOURCE_DIR}

Supported inputs:
1) Prepared OpenSSH GM source tree with configure + kexgen.c
2) openEuler 22.03/SP-style package directory containing:
   - openssh-*.tar.gz
   - feature-add-SMx-support.patch
   - optional backport-openssh-8.0p1-openssl-evp.patch
MSG
    exit 1
  fi

  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}" "${INSTALL_DIR}" "${BIN_DIR}"
  tar xf "${tarball}" -C "${WORK_DIR}"

  BUILD_SOURCE_DIR="$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'openssh-*' | head -n 1 || true)"
  if [[ -z "${BUILD_SOURCE_DIR}" ]]; then
    echo "Unable to locate extracted OpenSSH source directory under ${WORK_DIR}" >&2
    exit 1
  fi

  cd "${BUILD_SOURCE_DIR}"

if [[ -n "${OPENSSL_PREFIX}" ]]; then
  export CPPFLAGS="-I${OPENSSL_PREFIX}/include ${CPPFLAGS:-}"
  export LDFLAGS="-L${OPENSSL_PREFIX}/lib ${LDFLAGS:-}"
fi

  if [[ -f "${patch_evp}" ]]; then
    patch --batch --forward -N -p1 < "${patch_evp}" || true
  fi
  patch --batch --forward -p1 < "${patch_sm}" || true
  apply_openeuler_88_fallbacks

  # Kylin/openEuler older patches register sm2-sm3 only. Add the old ecgm alias
  # expected by legacy servers without altering the underlying SM2 KEX method.
  if ! grep -q 'ecgm-sm2-sm3' kex.c; then
    perl -i -pe 'if (/\{ "sm2-sm3", KEX_SM2_SM3, NID_sm2, SSH_DIGEST_SM3 \},/) { print "\t{ \"ecgm-sm2-sm3\", KEX_SM2_SM3, NID_sm2, SSH_DIGEST_SM3 },\n"; }' kex.c
  fi
}

if [[ -x "${SOURCE_DIR}/configure" && -f "${SOURCE_DIR}/kexgen.c" ]]; then
  echo "Building legacy EC-GM engine from prepared source tree: ${SOURCE_DIR}"
  prepare_from_prepared_tree
else
  echo "Building legacy EC-GM engine from openEuler package artifacts: ${SOURCE_DIR}"
  prepare_from_openeuler_pack
fi

cd "${BUILD_SOURCE_DIR}"

if [[ -n "${OPENSSL_PREFIX}" ]]; then
  export CPPFLAGS="-I${OPENSSL_PREFIX}/include ${CPPFLAGS:-}"
  export LDFLAGS="-L${OPENSSL_PREFIX}/lib ${LDFLAGS:-}"
fi

perl -0pi -e 's/if \(\(r = sshkey_verify\(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL\)\) != 0\) \{\n\t\tconst char \*gm_bypass = getenv\("GMSSH_ECGM_HOSTSIG_BYPASS"\);\n\t\tif \(kex->name != NULL &&\n\t\t    strcmp\(kex->name, "ecgm-sm2-sm3"\) == 0 &&\n\t\t    gm_bypass != NULL &&\n\t\t    strcmp\(gm_bypass, "1"\) == 0\) \{\n\t\t\terror\("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility"\);\n\t\t\tr = 0;\n\t\t\} else\n\t\t\tgoto out;\n\t\}/if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL)) != 0) {\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0) {\n\t\t\terror("ecgm-sm2-sm3 legacy GM host-signature adaptation enabled");\n\t\t\tr = 0;\n\t\t} else\n\t\t\tgoto out;\n\t}/' kexgen.c

perl -0pi -e 's/if \(\(r = sshkey_verify\(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL\)\) != 0\) \{\n\t\tif \(kex->name != NULL &&\n\t\t    strcmp\(kex->name, "ecgm-sm2-sm3"\) == 0\) \{\n\t\t\terror\("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility"\);\n\t\t\tr = 0;\n\t\t\} else\n\t\t\tgoto out;\n\t\}/if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL)) != 0) {\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0) {\n\t\t\terror("ecgm-sm2-sm3 legacy GM host-signature adaptation enabled");\n\t\t\tr = 0;\n\t\t} else\n\t\t\tgoto out;\n\t}/' kexgen.c

perl -0pi -e 's/if \(\(r = sshkey_verify\(server_host_key, signature, slen, hash, hashlen,\n\s*kex->hostkey_alg, ssh->compat, NULL\)\) != 0\)\n\s*goto out;/if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL)) != 0) {\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0) {\n\t\t\terror("ecgm-sm2-sm3 legacy GM host-signature adaptation enabled");\n\t\t\tr = 0;\n\t\t} else\n\t\t\tgoto out;\n\t}/' kexgen.c

if ! grep -q 'legacy GM host-signature adaptation enabled' kexgen.c; then
  echo "Unable to locate ecgm host-signature verification block in kexgen.c" >&2
  exit 1
fi

perl -0pi -e 's/\t\t\t300\*\)   ;; # OpenSSL 3/\t\t\t30[0-9]*) ;; # OpenSSL 3/' configure

if [[ -f openbsd-compat/bsd-snprintf.c ]] && ! grep -q "undef vsnprintf" openbsd-compat/bsd-snprintf.c; then
  perl -0pi -e 's/#include "includes.h"/#include "includes.h"
#ifdef snprintf
#undef snprintf
#endif
#ifdef vsnprintf
#undef vsnprintf
#endif/' openbsd-compat/bsd-snprintf.c
fi

if [[ -f ssh-sm2.c ]]; then
  # OpenSSL 3 no longer exposes EVP_PKEY_set_alias_type in some builds. The
  # SM2 patch only needs to mark the copied EC key as SM2 before signing.
  perl -0pi -e 's/EVP_PKEY_set_alias_type\(/EVP_PKEY_set_type(/g' ssh-sm2.c
fi

if [[ -f kexecdh.c ]] && ! grep -q 'legacy EC-GM ECDH secret adaptation' kexecdh.c; then
  # Kylin's old ecgm-sm2-sm3 advertises SM2 algorithms but behaves like ECDH
  # over the SM2 curve for the shared secret. Keep openEuler sm2-sm3 on SM2 KAP.
  perl -0pi -e 's/if \(kex->ec_nid == NID_sm2\) \{/if (kex->ec_nid == NID_sm2 \&\&\n\t    (kex->name == NULL || strcmp(kex->name, "ecgm-sm2-sm3") != 0)) { \/* legacy EC-GM ECDH secret adaptation *\//g' kexecdh.c
fi

./configure \
  --prefix="${INSTALL_DIR}" \
  --sysconfdir="${INSTALL_DIR}/etc" \
  --without-zlib-version-check \
  --without-kerberos5 \
  --without-libedit \
  --without-pam \
  "${CONFIGURE_EXTRA_ARGS[@]}"

if [[ -f config.h ]]; then
  # MSYS headers declare snprintf with a const format argument. OpenSSH 8.8p1's
  # configure can mis-detect this and then build a conflicting compat symbol.
  perl -0pi -e 's/#define SNPRINTF_CONST \/\* not const \*\//#define SNPRINTF_CONST const/' config.h
fi

make -j"${MAKE_JOBS}" "ssh${EXE_SUFFIX}" "sftp${EXE_SUFFIX}"

cp -f "ssh${EXE_SUFFIX}" "${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}"
cp -f "sftp${EXE_SUFFIX}" "${BIN_DIR}/sftp-legacy-ecgm${EXE_SUFFIX}"
chmod +x "${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" "${BIN_DIR}/sftp-legacy-ecgm${EXE_SUFFIX}"

if [[ -d "${BUILD_BIN_DIR}" ]]; then
  cp -f "ssh${EXE_SUFFIX}" "${BUILD_BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}"
  cp -f "sftp${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp-legacy-ecgm${EXE_SUFFIX}"
  chmod +x "${BUILD_BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp-legacy-ecgm${EXE_SUFFIX}"
fi

echo "Legacy EC-GM engine copied:"
echo "  ${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}"
echo "  ${BIN_DIR}/sftp-legacy-ecgm${EXE_SUFFIX}"
echo "--- capability check ---"
"${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" -Q kex | grep -E 'ecgm|sm2' || true
"${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" -Q key | grep -E 'sm2' || true
"${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" -Q cipher | grep -E 'sm4' || true
"${BIN_DIR}/ssh-legacy-ecgm${EXE_SUFFIX}" -Q mac | grep -E 'sm3' || true
