# 国密兼容矩阵（V1 当前实测）

最后验证日期：2026-04-29（真实联调环境）

## 1) 客户端引擎能力（modern 引擎 `bin/ssh -Q`）

- KEX: `ecgm-sm2-sm3`, `sm2-sm3`
- HostKey: `sm2`, `sm2-cert`
- Cipher: `sm4-ctr`
- MAC: `hmac-sm3`

## 2) 真实主机互通结果

| 目标主机 | 服务端模式 | 客户端策略 | 结果 | 说明 |
| --- | --- | --- | --- | --- |
| `10.0.13.2` | 常规 SSH（ED25519 + curve25519） | `standard_only` / `auto` | 通过 | 可登录并执行命令 |
| `10.0.13.2` | 常规 SSH | `gm_only` | 失败（预期） | 服务端未提供国密 KEX |
| `10.0.13.2:2222` | openEuler 独立纯国密服务（`gmsshd-debug.service`，`sm2-sm3`） | `gm_only`（强制国密参数） | 通过 | 持久化 systemd 服务，协商 `sm2-sm3/sm2/sm4-ctr/hmac-sm3`，terminal/SFTP/端口转发通过 |
| `10.0.13.2:2224` | openEuler 纯国密调试端口 | `gm_only`（强制国密参数） | 未启用 | 当前端口未监听 |
| `10.0.13.2:22` | openEuler 系统服务改为纯国密 | `gm_only`（强制国密参数） | 失败（服务端） | 服务端日志为 `fatal: No supported key exchange algorithms [preauth]`，属于服务端配置/启动链路问题 |
| `10.0.13.1` | 麒麟纯国密（`ecgm-sm2-sm3` + `sm2` + `sm4-ctr`） | 严格模式 + `gm_only` / `auto(优先国密)` | 失败（预期） | 严格模式不会启用绕过 |
| `10.0.13.1` | 麒麟 SP3 2403 纯国密（`ecgm-sm2-sm3` + `sm2` + `sm4-ctr`） | 旧版国密适配 + `gm_only` / `auto(优先国密)` | 通过（legacy 回退） | modern 会触发 `message authentication code incorrect`，GUI 自动切到 legacy ecgm 引擎后可登录 |

## 2.1) 2026-04-29 本轮握手与功能回归

| 目标 | 引擎/策略 | 外部观测结果 | 结论 |
| --- | --- | --- | --- |
| `10.0.13.1:22` | modern + `gm_only` + 旧版国密适配 | 协商到 `ecgm-sm2-sm3/sm2/sm4-ctr/hmac-sm3`，随后 `message authentication code incorrect` | modern 不适配麒麟 ecgm 运行时 |
| `10.0.13.1:22` | legacy + `gm_only` + 旧版国密适配 | 协商到 `ecgm-sm2-sm3/sm2/sm4-ctr/hmac-sm3`，无 MAC/KEX 错误，到达认证边界 | legacy 可作为麒麟 ecgm 旧版国密引擎 |
| `10.0.13.1:22` | legacy `sftp -S legacy ssh` + `gm_only` + 旧版国密适配 | 不再调用 `/tmp/gmssh-engine-install/bin/ssh`，且 stdin 驱动模式会调用 `SSH_ASKPASS` | P1 矩阵中 SFTP 列目录通过，硬编码 SSH 路径和 `-b` 禁用密码问题已规避 |
| `10.0.13.1:22` | standard | `no matching key exchange method found`，服务端 offer 为 `ecgm-sm2-sm3` | 确认该服务端为纯国密 ecgm |
| `10.0.13.2:22` | modern + standard | 协商到 `curve25519-sha256/ssh-ed25519/aes/hmac-sha2`，到达认证边界 | 当前 `:22` 仍是常规 SSH 服务 |
| `10.0.13.2:22` | modern + `gm_only` | `no matching key exchange method found`，服务端 offer 为 `curve25519-sha256,...` | `:22` 尚未处于纯国密服务端模式 |
| `10.0.13.2:2222` | modern + `gm_only` | 协商到 `sm2-sm3/sm2/sm4-ctr/hmac-sm3`，无 MAC/KEX 错误，到达认证边界 | openEuler 隔离纯国密服务端链路通过 |
| `10.0.13.2:2222` | modern + `gm_only` + 密码认证 | `Authenticated ... using "password"`，远端命令返回 `gm_login_ok=1` | 纯国密链路完整登录通过 |
| `10.0.13.2:2224` | TCP 端口探测 | 当前连接被拒绝 | 端口未启用 |

功能验证证据：

- P1 矩阵报告：`build/p1-matrix/20260429-101803/p1-matrix-report.json`，全部用例通过。
- openEuler systemd 化后功能报告：`build/openeuler-functional/20260429-101619-systemd/summary.json`，terminal、SFTP 上传/下载/重命名/删除、端口转发全部通过。

## 2.2) openEuler 纯国密服务端排障入口

当前结论：`10.0.13.2:22` 保持常规 SSH 服务；`10.0.13.2:2222` 是独立持久化纯国密验证端口，由 `gmsshd-debug.service` 管理。客户端在 `:22` 上 `gm_only` 失败是服务端未提供国密 KEX 的预期结果，不是客户端算法注入失败。

不要直接改系统 22 端口。推荐在 openEuler 上安装独立纯国密验证服务：

```bash
sudo GMSSHD_DEBUG_PORT=2222 \
  GMSSHD_KEX_ALGORITHMS=sm2-sm3 \
  /path/to/scripts/openeuler_gm_sshd_debug.sh doctor

sudo GMSSHD_DEBUG_PORT=2222 \
  GMSSHD_KEX_ALGORITHMS=sm2-sm3 \
  /path/to/scripts/openeuler_gm_sshd_debug.sh install-service
```

如果厂家/系统实际启用的是 `ecgm-sm2-sm3`，用：

```bash
sudo GMSSHD_DEBUG_PORT=2222 \
  GMSSHD_KEX_ALGORITHMS=ecgm-sm2-sm3 \
  /path/to/scripts/openeuler_gm_sshd_debug.sh install-service
```

状态检查：

```bash
sudo /path/to/scripts/openeuler_gm_sshd_debug.sh status
systemctl status gmsshd-debug.service
```

服务成功后，在客户端本机跑：

```bash
GMSSH_OPENEULER_GM_PORT=2222 scripts/gm_handshake_regression.sh
```

判断标准：

- `doctor` 阶段 `validate_config_ok=1`：服务端接受纯国密配置。
- `install-service` 阶段 `service_active=active` 且 `port_listening=1`：独立纯国密服务已经监听。
- 客户端回归出现 `kex: algorithm: sm2-sm3` 或 `ecgm-sm2-sm3`：进入国密 KEX。
- 如果 `doctor` 就失败，问题在 openEuler 服务端二进制/补丁/配置，不在客户端。
- 如果 `doctor/install-service` 通过但客户端仍 `no matching key exchange`，问题是服务端实际 offer 与客户端配置不一致。

## 3) 已支持范围

- 标准 SSH 主机（常规算法）完整支持。
- 国密算法参数注入与协商支持：`ecgm/sm2/sm3/sm4`。
- openEuler 纯国密 `sm2-sm3`：客户端 modern 引擎已通过独立持久化端口 `10.0.13.2:2222` 验证，含密码登录执行命令、SFTP 上传/下载/重命名/删除、端口转发。
- 麒麟 `ecgm-sm2-sm3`：严格模式仍按预期失败；旧版国密适配下 modern 出现 `MAC incorrect` 时自动切到 legacy 引擎，GUI 终端已验证。
- SFTP 批处理已绑定 `-S <selected ssh>`，会跟随 modern/legacy 引擎回退，并记录 `sftp_engine_fallback` 审计事件。
- 密码型 SFTP 不使用 `sftp -b`，因为 OpenSSH 会强制 `BatchMode=yes` 并禁用密码/askpass；当前通过 stdin 写入 SFTP 命令。
- 当本地引擎不支持国密参数时，可在 `auto` 模式回退常规算法，并记录审计事件。
- 已实现双引擎自动回退：
  - `message authentication code incorrect`：modern -> legacy
  - `verify KEX signature: unexpected internal error`：legacy -> modern
  - 回退事件写入审计日志：`engine_fallback` / `sftp_engine_fallback`

## 4) 当前不支持/风险项（必须明确）

- 风险项（当前版本）：  
  `ecgm-sm2-sm3` 需要旧版国密适配，且麒麟样机依赖 legacy 引擎回退，不能作为严格校验生产可用能力声明。
- 服务端策略：  
  openEuler 不改系统 `:22`；纯国密能力固定在独立 `gmsshd-debug.service` / `:2222` 验证。将系统 `sshd` 直接改为纯国密曾出现 `No supported key exchange algorithms`（服务端预认证阶段），不作为当前客户端验收阻塞项。
- 不支持（需求延期）：  
  USBKey / PKCS#11 实机接入（V1.1 处理）。
- 未完成验证：  
  `sm2_key` / `openssh_cert` / `x509_sm2_cert` 在纯国密主机上的全量正向用例。

## 5) 客户端内置的不支持识别码

- `local_client_gm_option_unsupported`：本地 SSH 引擎不识别国密参数。
- `gm_probe_algorithm_mismatch`：远端未接受当前算法组合。
- `gm_probe_runtime_incompatible`：已完成国密协商，但运行时在 KEX 阶段后出现内部错误。

## 6) 验收与下一步建议（按优先级）

已归档：

- GUI 正式验收记录见 `docs/gui-acceptance-2026-04-29.md`。本轮记录覆盖麒麟和 openEuler 的 GUI 终端、SFTP、连接状态与 openEuler 端口转发证据。
- macOS 打包验收记录见 `docs/package-acceptance-2026-04-29.md`。本轮记录确认 App bundle / DMG 内置 modern 与 legacy `ssh`/`sftp`，且包内引擎 P1 矩阵 9/9 通过。

1. 清理发布质量项：处理 CPack `install_name_tool -delete_rpath` 非致命警告，并补正式签名/公证流程。
2. 补小粒度回归测试：SFTP ControlPath 按算法/策略隔离、legacy->modern 与 modern->legacy 引擎回退顺序。
3. 补认证矩阵：`sm2_key` / `openssh_cert` / `x509_sm2_cert` 在纯国密主机上的正向用例。
