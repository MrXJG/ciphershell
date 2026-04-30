#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${GMSSH_ENGINE_PACK_DIR:-${ROOT_DIR}/engine/openssh-gm}"
WORK_DIR="${GMSSH_ENGINE_WORK_DIR:-/tmp/gmssh-engine-work}"
INSTALL_DIR="${GMSSH_ENGINE_INSTALL_DIR:-/tmp/gmssh-engine-install}"
BIN_DIR="${ROOT_DIR}/bin"
BUILD_BIN_DIR="${ROOT_DIR}/build/bin"
EXE_SUFFIX=""
case "$(uname -s 2>/dev/null || true)" in
  CYGWIN*|MSYS*|MINGW*) EXE_SUFFIX=".exe" ;;
esac

OPENSSL_PREFIX="${GMSSH_OPENSSL_PREFIX:-}"
if [[ -z "${OPENSSL_PREFIX}" ]] && command -v brew >/dev/null 2>&1; then
  if brew --prefix openssl@3 >/dev/null 2>&1; then
    OPENSSL_PREFIX="$(brew --prefix openssl@3)"
  fi
fi

build_source_tree() {
  local source_dir="$1"
  local old_cppflags="${CPPFLAGS:-}"
  local old_ldflags="${LDFLAGS:-}"

  mkdir -p "${INSTALL_DIR}" "${BIN_DIR}"
  cd "${source_dir}"

  if [[ ! -x configure ]]; then
    echo "Missing configure in source tree: ${source_dir}"
    echo "Provide a prepared source tree or package artifacts that expand to an OpenSSH tree with configure."
    exit 1
  fi

  if [[ -n "${OPENSSL_PREFIX}" ]]; then
    export CPPFLAGS="-I${OPENSSL_PREFIX}/include ${old_cppflags}"
    export LDFLAGS="-L${OPENSSL_PREFIX}/lib ${old_ldflags}"
  fi

  ./configure \
    --prefix="${INSTALL_DIR}" \
    --sysconfdir="${INSTALL_DIR}/etc" \
    --without-zlib-version-check \
    --without-kerberos5 \
    --without-libedit \
    --without-pam

  make -j"$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)" "ssh${EXE_SUFFIX}" "sftp${EXE_SUFFIX}"

  cp -f "ssh${EXE_SUFFIX}" "${BIN_DIR}/ssh${EXE_SUFFIX}"
  cp -f "sftp${EXE_SUFFIX}" "${BIN_DIR}/sftp${EXE_SUFFIX}"
  cp -f "ssh${EXE_SUFFIX}" "${BIN_DIR}/ssh-modern${EXE_SUFFIX}"
  cp -f "sftp${EXE_SUFFIX}" "${BIN_DIR}/sftp-modern${EXE_SUFFIX}"

  chmod +x "${BIN_DIR}/ssh${EXE_SUFFIX}" "${BIN_DIR}/sftp${EXE_SUFFIX}" \
    "${BIN_DIR}/ssh-modern${EXE_SUFFIX}" "${BIN_DIR}/sftp-modern${EXE_SUFFIX}"
  if [[ -d "${BUILD_BIN_DIR}" ]]; then
    cp -f "ssh${EXE_SUFFIX}" "${BUILD_BIN_DIR}/ssh${EXE_SUFFIX}"
    cp -f "sftp${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp${EXE_SUFFIX}"
    cp -f "ssh${EXE_SUFFIX}" "${BUILD_BIN_DIR}/ssh-modern${EXE_SUFFIX}"
    cp -f "sftp${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp-modern${EXE_SUFFIX}"
    chmod +x "${BUILD_BIN_DIR}/ssh${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp${EXE_SUFFIX}" \
      "${BUILD_BIN_DIR}/ssh-modern${EXE_SUFFIX}" "${BUILD_BIN_DIR}/sftp-modern${EXE_SUFFIX}"
  fi
  echo "Bundled engine copied to ${BIN_DIR}"
  echo "OpenSSL prefix: ${OPENSSL_PREFIX:-system default}"
  echo "--- capability check ---"
  "${BIN_DIR}/ssh${EXE_SUFFIX}" -Q kex | grep -E 'ecgm|sm2' || true
  "${BIN_DIR}/ssh${EXE_SUFFIX}" -Q cipher | grep -E 'sm4' || true
  "${BIN_DIR}/ssh${EXE_SUFFIX}" -Q mac | grep -E 'sm3' || true
}

ensure_env_gated_ecgm_bypass() {
  # Kylin pure-GM compatibility:
  # Default is strict host-signature verification.
  # Only when runtime env GMSSH_ECGM_HOSTSIG_BYPASS=1, allow ecgm-only bypass.
  if ! grep -q '#include <stdlib.h>' kexgen.c; then
    perl -0pi -e 's/#include <string.h>/#include <string.h>\n#include <stdlib.h>/' kexgen.c
  fi

  if ! grep -q 'GMSSH_ECGM_HOSTSIG_BYPASS' kexgen.c; then
    perl -0pi -e 's/if \(\(r = sshkey_verify\(server_host_key, signature, slen, hash, hashlen,\n\s*kex->hostkey_alg, ssh->compat, NULL\)\) != 0\)\n\s*goto out;/if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL)) != 0) {\n\t\tconst char *gm_bypass = getenv("GMSSH_ECGM_HOSTSIG_BYPASS");\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0 &&\n\t\t    gm_bypass != NULL &&\n\t\t    strcmp(gm_bypass, "1") == 0) {\n\t\t\terror("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility");\n\t\t\tr = 0;\n\t\t} else\n\t\t\tgoto out;\n\t}/' kexgen.c

    perl -0pi -e 's/if \(\(r = sshkey_verify\(server_host_key, signature, slen, hash, hashlen,\n\s*kex->hostkey_alg, ssh->compat, NULL\)\) != 0\) \{\n\s*if \(kex->name != NULL &&\n\s*strcmp\(kex->name, "ecgm-sm2-sm3"\) == 0\) \{\n\s*error\("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility"\);\n\s*r = 0;\n\s*\} else\n\s*goto out;\n\s*\}/if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,\n\t    kex->hostkey_alg, ssh->compat, NULL)) != 0) {\n\t\tconst char *gm_bypass = getenv("GMSSH_ECGM_HOSTSIG_BYPASS");\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0 &&\n\t\t    gm_bypass != NULL &&\n\t\t    strcmp(gm_bypass, "1") == 0) {\n\t\t\terror("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility");\n\t\t\tr = 0;\n\t\t} else\n\t\t\tgoto out;\n\t}/' kexgen.c

    # Some patchsets already carry an ecgm bypass block with an error_fr() fallback branch.
    # Convert that shape to env-gated behavior as well.
    perl -0pi -e 's/if \(kex->name != NULL && strcmp\(kex->name, "ecgm-sm2-sm3"\) == 0\) \{/const char *gm_bypass = getenv("GMSSH_ECGM_HOSTSIG_BYPASS");\n\t\tif (kex->name != NULL &&\n\t\t    strcmp(kex->name, "ecgm-sm2-sm3") == 0 &&\n\t\t    gm_bypass != NULL &&\n\t\t    strcmp(gm_bypass, "1") == 0) {/g' kexgen.c
  fi

  # Safety guard: if compatibility bypass string exists, it must be env-gated.
  if grep -q 'host signature verify bypass enabled for compatibility' kexgen.c && \
     ! grep -q 'GMSSH_ECGM_HOSTSIG_BYPASS' kexgen.c; then
    echo "Failed to apply env-gated ecgm host-signature bypass patch in kexgen.c"
    exit 1
  fi
}

apply_oe_patch_fallbacks() {
  # openEuler patches may partially fail on vanilla portable tarballs.
  # Fill critical pieces so the resulting client is still SM2/SM3/SM4-capable.
  if ! grep -q 'ssh-sm2.o' Makefile.in; then
    perl -0pi -e 's/ssh-dss\.o ssh-ecdsa\.o ssh-ecdsa-sk\.o/ssh-dss.o ssh-ecdsa.o ssh-sm2.o ssh-ecdsa-sk.o/' Makefile.in
  fi
  if ! grep -q 'kexsm2.o' Makefile.in; then
    perl -0pi -e 's/kex\.o kexdh\.o kexgex\.o kexecdh\.o kexc25519\.o/kex.o kexdh.o kexgex.o kexecdh.o kexc25519.o kexsm2.o/' Makefile.in
  fi
  if ! grep -q 'KEX_SM2_SM3' kex.h; then
    perl -0pi -e 's/(KEX_KEM_SNTRUP761X25519_SHA512,\n)/$1\tKEX_SM2_SM3,\n/' kex.h
  fi
  if ! grep -q 'extern const struct sshkey_impl sshkey_sm2_impl;' sshkey.c; then
    perl -0pi -e 's/(#endif\nextern const struct sshkey_impl sshkey_xmss_impl;\nextern const struct sshkey_impl sshkey_xmss_cert_impl;\n#endif\n)/$1extern const struct sshkey_impl sshkey_sm2_impl;\nextern const struct sshkey_impl sshkey_sm2_cert_impl;\n/' sshkey.c
  fi
  if ! grep -q '&sshkey_sm2_impl' sshkey.c; then
    perl -0pi -e 's/# endif \/\* OPENSSL_HAS_ECC \*\/\n\t&sshkey_dss_impl,/# endif \/\* OPENSSL_HAS_ECC \*\/\n\t\&sshkey_sm2_impl,\n\t\&sshkey_sm2_cert_impl,\n\t&sshkey_dss_impl,/' sshkey.c
  fi
  if ! grep -q 'is_ecdsa_pkcs11(EC_KEY \*ecdsa);' ssh-pkcs11.h; then
    perl -0pi -e 's/#endif \/\* ENABLE_PKCS11 \*\//int is_ecdsa_pkcs11(EC_KEY *ecdsa);\nint is_rsa_pkcs11(RSA *rsa);\n#endif \/\* ENABLE_PKCS11 \*\//' ssh-pkcs11.h
  fi
  if ! grep -q '^is_ecdsa_pkcs11(EC_KEY \*ecdsa)' ssh-pkcs11.c; then
    cat >> ssh-pkcs11.c <<'EOF'

int
is_ecdsa_pkcs11(EC_KEY *ecdsa)
{
#if defined(OPENSSL_HAS_ECC) && defined(HAVE_EC_KEY_METHOD_NEW)
	if (EC_KEY_get_ex_data(ecdsa, ec_key_idx) != NULL)
		return 1;
#endif
	return 0;
}

int
is_rsa_pkcs11(RSA *rsa)
{
	if (RSA_get_ex_data(rsa, rsa_idx) != NULL)
		return 1;
	return 0;
}
EOF
  fi
  # Older EVP patch variants reference debug2_f() that is not present in portable 9.6.
  perl -0pi -e 's/^\s*debug2_f\([^\n;]*\);\n//mg' sshkey.c
  perl -0pi -e 's/^\s*debug2\("param_bld or ctx is NULL"\);\n//mg; s/^\s*debug2\("Could not build param list"\);\n//mg; s/^\s*debug2\("EVP_PKEY_fromdata failed"\);\n//mg' sshkey.c
}

prepare_from_pack() {
  local tarball
  local patch_sm
  local patch_evp
  local patch_openssl
  local source_dir

  if [[ ! -d "${PACK_DIR}" ]]; then
    cat <<MSG
Missing package dir: ${PACK_DIR}

Two supported inputs:
1) A prepared OpenSSH source tree at:
   ${PACK_DIR}
   (must contain configure + ssh.c)
2) openEuler-style source package files under:
   ${PACK_DIR}
   - openssh-*.tar.gz
   - openssh-9.3p1-merged-openssl-evp.patch
   - feature-add-SMx-support.patch
   - backport-Remove-status-bits-from-OpenSSL-3-version-check.patch
MSG
    exit 1
  fi

  tarball="$(find "${PACK_DIR}" -maxdepth 1 -type f -name 'openssh-*.tar.gz' | head -n 1 || true)"
  patch_evp="${PACK_DIR}/openssh-9.3p1-merged-openssl-evp.patch"
  patch_sm="${PACK_DIR}/feature-add-SMx-support.patch"
  patch_openssl="${PACK_DIR}/backport-Remove-status-bits-from-OpenSSL-3-version-check.patch"

  if [[ -z "${tarball}" || ! -f "${patch_evp}" || ! -f "${patch_sm}" || ! -f "${patch_openssl}" ]]; then
    cat <<MSG
Missing package artifacts under ${PACK_DIR}

Required:
- openssh-*.tar.gz
- openssh-9.3p1-merged-openssl-evp.patch
- feature-add-SMx-support.patch
- backport-Remove-status-bits-from-OpenSSL-3-version-check.patch
MSG
    exit 1
  fi

  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}"
  tar xf "${tarball}" -C "${WORK_DIR}"

  source_dir="$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'openssh-*' | head -n 1 || true)"
  if [[ -z "${source_dir}" ]]; then
    echo "Unable to locate extracted OpenSSH source directory under ${WORK_DIR}"
    exit 1
  fi

  cd "${source_dir}"

  patch --batch --forward -N -p1 < "${patch_evp}" || true
  patch --batch --forward -p1 < "${patch_sm}" || true

  apply_oe_patch_fallbacks

  if ! grep -q 'ecgm-sm2-sm3' kex.c; then
    perl -i -pe 'if (/\{ "sm2-sm3", KEX_SM2_SM3, NID_sm2, SSH_DIGEST_SM3 \},/) { print "\t{ \"ecgm-sm2-sm3\", KEX_SM2_SM3, NID_sm2, SSH_DIGEST_SM3 },\n"; }' kex.c
  fi

  ensure_env_gated_ecgm_bypass

  if ! grep -q 'obj_mac.h' kexecdh.c; then
    perl -0pi -e 's/#include <openssl\/ecdh.h>/#include <openssl\/ecdh.h>\n#include <openssl\/obj_mac.h>/' kexecdh.c
  fi

  patch --batch --forward -N -p1 < "${patch_openssl}" || true

  perl -0pi -e 's/301\*\|302\*\|303\*\)/301*|302*|303*|304*|305*|306*|307*|308*|309*)/g' configure

  build_source_tree "${source_dir}"
}

if [[ -x "${PACK_DIR}/configure" && -f "${PACK_DIR}/ssh.c" ]]; then
  echo "Building from prepared source tree: ${PACK_DIR}"
  cd "${PACK_DIR}"
  ensure_env_gated_ecgm_bypass
  build_source_tree "${PACK_DIR}"
else
  echo "Building from package artifacts: ${PACK_DIR}"
  prepare_from_pack
fi
