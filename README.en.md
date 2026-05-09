# CipherShell (V1)

[English](README.en.md) | [简体中文](README.md)

Qt/C++ SSH GUI client with GM-aware algorithm policy and OpenSSH engine adapter.

## Implemented capabilities

- Multi-session terminal tabs (process-backed)
- Profile management (`profiles.json`)
- Auth modes: `password`, `sm2_key`, `openssh_cert`, `x509_sm2_cert`
- Algorithm policy: `auto`, `gm_only`, `standard_only`
- Forwarding rules: `local`, `remote`, `dynamic_socks`, `unix_socket`
- SFTP browser panel (`ls/put/get/rename/mkdir/rm/rmdir/chmod`) with engine fallback diagnostics
- Audit log view (JSON lines)
- Encrypted credential storage (local encrypted blob; never plaintext)
- OpenSSH engine integration entrypoint (`scripts/build_openssh_engine.sh`)
- GM algorithm preset: `KexAlgorithms=ecgm-sm2-sm3,sm2-sm3`, `Ciphers=sm4-ctr`, `MACs=hmac-sm3`
- GM host-signature policy switch (UI): strict (default) / legacy-GM adaptation
- Dual-engine auto fallback (modern <-> legacy) for GM runtime compatibility
- ecgm host-signature policy:
  - default strict mode (recommended): strict host-signature verification
  - legacy GM adaptation mode: only when runtime sets `GMSSH_ECGM_HOSTSIG_BYPASS=1`;
    UI/logs describe this as `旧版国密适配（降低校验强度）`
    (security tradeoff; see compatibility matrix)

## Build

### macOS arm64

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### macOS package verification

```bash
scripts/package_macos_app.sh
```

This creates `build/CipherShell.app`, deploys Qt dependencies, bundles
modern and legacy SSH/SFTP engines under `Contents/MacOS/bin`, runs the P1
matrix with the packaged engines, and emits `build/ciphershell-0.1.1-Darwin.dmg`.
Set `GMSSH_RUN_PACKAGE_P1=0` to skip remote interoperability checks.

### Windows x64 (MSVC)

```powershell
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Packaging

```bash
cmake --build build --target package
```

- macOS: DMG
- Windows: NSIS package

## GM Engine Build

```bash
scripts/build_openssh_engine.sh
```

If your package files are not in `engine/openssh-gm`, set:

```bash
GMSSH_ENGINE_PACK_DIR=/path/to/openssh-package-dir scripts/build_openssh_engine.sh
```

Required package artifacts for the GM engine script:

- `openssh-*.tar.gz` (`9.6p1` baseline)
- `openssh-9.3p1-merged-openssl-evp.patch`
- `feature-add-SMx-support.patch`
- `backport-Remove-status-bits-from-OpenSSL-3-version-check.patch`

Recommended source: `src-openeuler/openssh` branch `openEuler-24.03-LTS-SP3`.

### Dual-engine runtime strategy

- Primary engine (modern): auto-resolved from app bundle `bin/ssh` / `bin/sftp` (or `GMSSH_SSH_PATH` / `GMSSH_SFTP_PATH`).
- Legacy compatibility engine (optional): auto-resolved from app bundle `bin/ssh-legacy-ecgm` / `bin/sftp-legacy-ecgm`, and can be forced by:
  - `GMSSH_SSH_LEGACY_PATH`
  - `GMSSH_SFTP_LEGACY_PATH`
  - `GMSSH_LEGACY_ENGINE_DIR`
- Auto switch rules:
  - `message authentication code incorrect` on GM probe: switch modern -> legacy
  - `verify KEX signature: unexpected internal error` on GM probe: switch legacy -> modern
- All auto switch events are written to audit log (`engine_fallback` / `sftp_engine_fallback`) and shown in terminal session startup logs.
- SFTP always passes `-S <selected ssh>` to avoid bundled `sftp` using a compile-time SSH path such as `/tmp/gmssh-engine-install/bin/ssh`.
- Password-based SFTP is driven through stdin instead of `sftp -b`; OpenSSH `sftp -b` forces `BatchMode=yes` and disables password/askpass authentication.
- SFTP caches the verified compatible engine per host/profile and uses SSH `ControlMaster` / `ControlPersist` for connection reuse, reducing repeated handshake latency.
- SFTP execution logs the selected `sftp`, selected `ssh`, negotiated mode, timeout state, and fallback reason to the audit log.

## Runtime paths

- Profiles: `${AppConfigLocation}/profiles.json`
- Credentials: `${AppConfigLocation}/credentials.json` (encrypted at rest)
- Known hosts: `${AppConfigLocation}/known_hosts`
- Audit:
  - Windows installer build: `<install-dir>/log/audit.log` when writable, for example
    `%LOCALAPPDATA%\Programs\CipherShell\log\audit.log`
  - Fallback / non-Windows: `${AppDataLocation}/log/audit.log`
  - The Audit Log window shows the effective log file path.

## Windows installer behavior

- Installs to `%LOCALAPPDATA%\Programs\CipherShell` by default.
- Creates a Start Menu shortcut and a Desktop shortcut named `CipherShell`.
- Bundles modern and legacy GM SSH/SFTP engines under `bin/`.
- Creates `log/audit.log` during install so audit output is discoverable.

## Interop smoke targets

Current environment targets:

- `10.0.13.1`
- `10.0.13.2`

Use root credentials in the GUI profile for first-run connectivity checks.

No-password handshake regression:

```bash
scripts/gm_handshake_regression.sh
```

The script checks KEX/cipher/MAC negotiation and authentication boundary only. It does not read or send login passwords.

To probe an isolated openEuler GM debug `sshd` port:

```bash
GMSSH_OPENEULER_GM_PORT=2222 scripts/gm_handshake_regression.sh
```

On the openEuler host, use the debug helper instead of changing the system port 22 service first:

```bash
sudo GMSSHD_DEBUG_PORT=2222 scripts/openeuler_gm_sshd_debug.sh doctor
sudo GMSSHD_DEBUG_PORT=2222 scripts/openeuler_gm_sshd_debug.sh start
```

Detailed GM compatibility matrix (supported / partial / unsupported):

- `docs/gm-compatibility-matrix.md`

## License

- This project is licensed under `GNU Affero General Public License v3.0` (`AGPL-3.0-only`).
- You may use and redistribute this software.
- If you distribute modified versions, or provide modified versions as a network service, you must make the corresponding source code available under AGPL v3.
- You must preserve copyright and attribution notices (see `NOTICE`).
