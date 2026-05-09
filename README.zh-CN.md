# CipherShell (V1)

[简体中文](README.md) | [English](README.en.md)

基于 Qt/C++ 的 SSH 图形客户端，内置国密算法策略与 OpenSSH 引擎适配能力。

> 作者博客（技术分享与生活记录）：[https://www.xiangjigong.top/](https://www.xiangjigong.top/)

## 已实现能力

- 多会话终端标签页（基于进程）
- 会话配置管理（`profiles.json`）
- 认证模式：`password`、`sm2_key`、`openssh_cert`、`x509_sm2_cert`
- 算法策略：`auto`、`gm_only`、`standard_only`
- 转发规则：`local`、`remote`、`dynamic_socks`、`unix_socket`
- SFTP 文件面板（`ls/put/get/rename/mkdir/rm/rmdir/chmod`），带引擎回退诊断
- 审计日志查看（JSON 行）
- 加密凭据存储（本地密文，不落明文）
- OpenSSH 引擎集成入口（`scripts/build_openssh_engine.sh`）
- 国密算法预设：`KexAlgorithms=ecgm-sm2-sm3,sm2-sm3`、`Ciphers=sm4-ctr`、`MACs=hmac-sm3`
- 国密主机签名策略切换（UI）：严格校验（默认）/ 旧版国密适配
- 双引擎自动回退（modern <-> legacy），用于国密兼容
- ecgm 主机签名策略：
  - 默认严格模式（推荐）：严格主机签名校验
  - 旧版国密适配模式：仅当运行时设置 `GMSSH_ECGM_HOSTSIG_BYPASS=1` 时启用；
    UI/日志中显示为 `旧版国密适配（降低校验强度）`
    （存在安全折中，详见兼容矩阵）

## 构建

### macOS arm64

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### macOS 打包验证

```bash
scripts/package_macos_app.sh
```

该脚本会生成 `build/CipherShell.app`，部署 Qt 依赖，将 modern/legacy 的 SSH/SFTP
引擎打入 `Contents/MacOS/bin`，并产出 `build/ciphershell-0.1.1-Darwin.dmg`。
如果需要跳过远端互通检查，可设置 `GMSSH_RUN_PACKAGE_P1=0`。

### Windows x64 (MSVC)

```powershell
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## 打包

```bash
cmake --build build --target package
```

- macOS：DMG
- Windows：NSIS 安装包

## 国密引擎构建

```bash
scripts/build_openssh_engine.sh
```

如果补丁包不在 `engine/openssh-gm`，可指定：

```bash
GMSSH_ENGINE_PACK_DIR=/path/to/openssh-package-dir scripts/build_openssh_engine.sh
```

国密引擎脚本所需产物：

- `openssh-*.tar.gz`（基线 `9.6p1`）
- `openssh-9.3p1-merged-openssl-evp.patch`
- `feature-add-SMx-support.patch`
- `backport-Remove-status-bits-from-OpenSSL-3-version-check.patch`

推荐来源：`src-openeuler/openssh` 的 `openEuler-24.03-LTS-SP3` 分支。

### 双引擎运行策略

- 主引擎（modern）：默认从应用包内 `bin/ssh` / `bin/sftp` 自动解析（也可由 `GMSSH_SSH_PATH` / `GMSSH_SFTP_PATH` 强制指定）
- 兼容引擎（legacy，可选）：默认从应用包内 `bin/ssh-legacy-ecgm` / `bin/sftp-legacy-ecgm` 自动解析，也可通过以下变量强制指定：
  - `GMSSH_SSH_LEGACY_PATH`
  - `GMSSH_SFTP_LEGACY_PATH`
  - `GMSSH_LEGACY_ENGINE_DIR`
- 自动切换规则：
  - 国密探测出现 `message authentication code incorrect`：modern -> legacy
  - 国密探测出现 `verify KEX signature: unexpected internal error`：legacy -> modern
- 所有自动切换事件会写入审计日志（`engine_fallback` / `sftp_engine_fallback`），并显示在终端会话启动日志中。
- SFTP 始终传入 `-S <selected ssh>`，避免打包 `sftp` 使用编译时硬编码 SSH 路径（例如 `/tmp/gmssh-engine-install/bin/ssh`）。
- 密码型 SFTP 通过 stdin 驱动，而不是 `sftp -b`；因为 OpenSSH 的 `sftp -b` 会强制 `BatchMode=yes`，导致密码/askpass 认证不可用。
- SFTP 会按主机/配置缓存已验证可用的兼容引擎，并使用 SSH `ControlMaster` / `ControlPersist` 复用连接，降低重复握手延迟。
- SFTP 执行日志会记录：选中的 `sftp`、选中的 `ssh`、协商模式、超时状态、回退原因。

## 运行时路径

- 会话配置：`${AppConfigLocation}/profiles.json`
- 凭据：`${AppConfigLocation}/credentials.json`（静态加密）
- 已知主机：`${AppConfigLocation}/known_hosts`
- 审计：
  - Windows 安装版：优先写入 `<install-dir>/log/audit.log`，例如
    `%LOCALAPPDATA%\Programs\CipherShell\log\audit.log`
  - 回退路径（或非 Windows）：`${AppDataLocation}/log/audit.log`
  - 审计日志窗口会显示实际生效的日志路径

## Windows 安装包行为

- 默认安装到 `%LOCALAPPDATA%\Programs\CipherShell`
- 创建开始菜单和桌面快捷方式，名称为 `CipherShell`
- 在 `bin/` 下打包 modern + legacy 两套国密 SSH/SFTP 引擎
- 安装阶段创建 `log/audit.log`，确保审计日志可发现

## 互通冒烟目标

当前环境目标主机：

- `10.0.13.1`
- `10.0.13.2`

首次连通检查请在 GUI 配置中填写 root 凭据。

无密码握手回归脚本：

```bash
scripts/gm_handshake_regression.sh
```

该脚本仅验证 KEX/加密/MAC 协商与认证边界，不会读取或发送登录密码。

如果要探测隔离的 openEuler 国密调试 `sshd` 端口：

```bash
GMSSH_OPENEULER_GM_PORT=2222 scripts/gm_handshake_regression.sh
```

在 openEuler 主机侧，建议先用调试脚本而非直接改系统 22 端口服务：

```bash
sudo GMSSHD_DEBUG_PORT=2222 scripts/openeuler_gm_sshd_debug.sh doctor
sudo GMSSHD_DEBUG_PORT=2222 scripts/openeuler_gm_sshd_debug.sh start
```

完整国密兼容矩阵（支持 / 部分支持 / 不支持）：

- `docs/gm-compatibility-matrix.md`

## 开源协议

- 本项目采用 `GNU Affero General Public License v3.0`（`AGPL-3.0-only`）。
- 你可以使用与再分发本软件。
- 如果你分发修改版本，或将修改版本作为网络服务提供，必须按 AGPL v3 提供对应源码。
- 你必须保留版权与署名声明（见 `NOTICE`）。
