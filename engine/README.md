# OpenSSH GM Engine

`scripts/build_openssh_engine.sh` supports two input modes.

## Mode A: Prepared source tree

Put a ready-to-build OpenSSH GM source tree at:

- `engine/openssh-gm/`

This directory must contain at least `configure` and `ssh.c`.

## Mode B: openEuler source package files (recommended bootstrap)

Put these files under:

- `engine/openssh-gm/`

Required files:

- `openssh-*.tar.gz`
- `feature-add-SMx-support.patch`
- `backport-Remove-status-bits-from-OpenSSL-3-version-check.patch`

The script will unpack, apply SM patches, add `ecgm-sm2-sm3` alias, and build `ssh` / `sftp`.

Current compatibility behavior for some Kylin pure-GM targets:

- Default is strict host-signature verification (no bypass).
- If runtime env `GMSSH_ECGM_HOSTSIG_BYPASS=1`, the engine enables ecgm-only
  compatibility bypass and prints:
  `ecgm-sm2-sm3 host signature verify bypass enabled for compatibility`
- Compatibility bypass is a temporary interoperability tradeoff and should be
  disabled in strict production security scenarios.

## Build command

```bash
scripts/build_openssh_engine.sh
```

Optional environment variables:

- `GMSSH_ENGINE_PACK_DIR=/path/to/package-or-source-dir`
- `GMSSH_OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3`
- `GMSSH_ENGINE_WORK_DIR=/tmp/gmssh-engine-work`
- `GMSSH_ENGINE_INSTALL_DIR=/tmp/gmssh-engine-install`

After build, these binaries are copied to project root:

- `bin/ssh`, `bin/sftp` (default modern engine)
- `bin/ssh-modern`, `bin/sftp-modern` (explicit modern alias)

If you also keep a legacy ecgm-compatible engine (for example `build/stage/bin/ssh`),
the GUI can auto-detect/use it as fallback or read explicit env vars:

- `GMSSH_SSH_LEGACY_PATH`
- `GMSSH_SFTP_LEGACY_PATH`
- `GMSSH_LEGACY_ENGINE_DIR`
