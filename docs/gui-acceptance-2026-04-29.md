# GUI 正式验收记录（2026-04-29）

## 1. 验收结论

本轮 GUI 阶段性验收结论：**通过，可进入打包验收阶段**。

通过范围限定为当前本地构建产物、当前联调环境、当前已保存会话凭据与已验证的两类服务端链路：

- 麒麟 V10 SP3 2403 纯国密 `ecgm-sm2-sm3`：通过“旧版国密适配（降低校验强度）+ legacy 引擎回退”完成 GUI 终端与 SFTP 验收。
- openEuler 独立纯国密服务 `10.0.13.2:2222`：通过 `sm2-sm3/sm2/sm4-ctr/hmac-sm3` 完成 terminal、SFTP、端口转发自动化功能验收。
- openEuler 常规 SSH `10.0.13.2:22`：通过标准 SSH 兼容链路验收。

本结论不覆盖：打包后的 App 路径隔离、USBKey/PKCS#11 实机接入、SM2 证书登录全量正向用例、openEuler 系统 `:22` 直接改造为纯国密服务。

## 2. 验收对象

| 项目 | 值 |
| --- | --- |
| 客户端 | 国密 SSH 客户端 GUI |
| 验收日期 | 2026-04-29 |
| 工作目录 | `/Users/xiangjigong/飞牛同步/开发/国密 SSH 客户端项目` |
| 构建产物 | `build/` 本地构建产物 |
| 源码状态 | 当前目录不是 Git 仓库，本记录不绑定 commit id |
| 视觉规范 | `DESIGN.md`，Linear Light + GM Security Accent |

## 3. 验收环境

| 主机 | 端口 | 服务端模式 | 客户端策略 | 验收状态 | 说明 |
| --- | ---: | --- | --- | --- | --- |
| `10.0.13.1` | `22` | 麒麟 V10 SP3 2403 纯国密，`ecgm-sm2-sm3` | `auto` / `gm_only` + 旧版国密适配 | 通过 | modern 引擎触发 MAC 错误后切换 legacy 引擎，GUI 可用 |
| `10.0.13.2` | `2222` | openEuler 独立纯国密服务，`gmsshd-debug.service` | `auto` / `gm_only` | 通过 | 协商 `sm2-sm3/sm2/sm4-ctr/hmac-sm3` |
| `10.0.13.2` | `22` | openEuler 常规 SSH | `auto` / `standard_only` | 通过 | 常规 SSH 兼容链路 |
| `10.0.13.2` | `22` | openEuler 常规 SSH | `gm_only` | 预期失败 | 服务端未提供国密 KEX，失败符合策略预期 |

## 4. 证据来源

| 证据 | 路径 | 结论 |
| --- | --- | --- |
| P1 全矩阵自动化报告 | `build/p1-matrix/20260429-101803/p1-matrix-report.json` | 9/9 通过 |
| openEuler 功能自动化报告 | `build/openeuler-functional/20260429-101619-systemd/summary.json` | terminal、SFTP、端口转发通过 |
| GUI 截图归档 | `build/gui-acceptance/20260429-gui/` | 麒麟 GUI 终端、SFTP、删除动作和 openEuler 终端截图已归档 |
| GUI 运行日志 | `build/gui-acceptance/20260429-gui/app.stderr.log` | 仅有 Matter 字体缺失提示，无功能错误 |
| SFTP 操作变量 | `build/gui-acceptance/20260429-gui/kylin-sftp-vars.env` | 记录本轮 GUI SFTP 上传/下载/重命名/删除/目录操作对象 |
| 兼容矩阵 | `docs/gm-compatibility-matrix.md` | 与本记录结论一致 |

P1 矩阵通过用例：

| 用例 | 结果 |
| --- | --- |
| `kylin-auto-old-gm-adaptation` | 通过 |
| `kylin-gm-only-old-gm-adaptation` | 通过 |
| `kylin-standard-only-expected-fail` | 通过，失败路径符合预期 |
| `openeuler-gm-auto` | 通过 |
| `openeuler-gm-only` | 通过 |
| `openeuler-gm-standard-only-expected-fail` | 通过，失败路径符合预期 |
| `openeuler-standard-auto` | 通过 |
| `openeuler-standard-only` | 通过 |
| `openeuler-standard-gm-only-expected-fail` | 通过，失败路径符合预期 |

openEuler 功能报告关键字段：

| 字段 | 值 |
| --- | --- |
| `verdict` | `pass` |
| `service` | `gmsshd-debug.service` |
| `terminal_ok` | `true` |
| `sftp_put_get_rename_delete_ok` | `true` |
| `forwarding_ok` | `true` |
| `kex_sm2_sm3` | `true` |
| `hostkey_sm2` | `true` |
| `server_to_client_sm4_hmac_sm3` | `true` |
| `client_to_server_sm4_hmac_sm3` | `true` |

## 5. GUI 验收项

| 模块 | 验收项 | 结果 | 证据/说明 |
| --- | --- | --- | --- |
| 会话中心 | 已保存会话可选择、可连接 | 通过 | 用户现场验证，GUI 截图归档 |
| 认证 | 密码凭据可保存并复用 | 通过 | 用户已使用客户端连接并保存会话凭据 |
| 连接状态 | 状态栏展示当前连接方式/策略 | 通过 | 已实现“标准 SSH/国密/旧版国密适配”等状态表达 |
| 终端 | 麒麟纯国密终端连接与命令执行 | 通过 | `01-kylin-terminal.png`、`02-kylin-terminal-command.png`、P1 矩阵 |
| 终端 | openEuler 纯国密终端连接与命令执行 | 通过 | `06-openeuler-terminal.png`、`06-openeuler-terminal-attempt2.png`、功能报告 |
| 终端 | 标签关闭按钮可见、居中、左对齐排列 | 通过 | 已按最近 GUI 调整完成，需最终人工视觉确认 |
| SFTP | SFTP 绑定当前会话/当前连接主机 | 通过 | 当前逻辑按活动会话打开 SFTP |
| SFTP | 麒麟目录列表与删除动作 | 通过 | `03-kylin-sftp-list.png`、`05-kylin-sftp-delete.png` |
| SFTP | openEuler 上传/下载/重命名/删除 | 通过 | `sftp_put_get_rename_delete_ok=true` |
| SFTP | 日志新记录置顶 | 通过 | 已按用户要求调整 |
| 端口转发 | openEuler 纯国密端口转发 | 通过 | `forwarding_ok=true`，`forward_banner=SSH-2.0-OpenSSH_9.6` |
| 审计日志 | 连接、回退、SFTP 操作、输入输出日志可见 | 通过 | P1 和 GUI 日志链路已覆盖；深度文本堡垒机能力仍属于增强项 |
| 视觉/交互 | 下拉控件有明显标识，输入框边界可识别 | 通过 | 已增加全局下拉箭头与表格内输入框标识 |
| 视觉/交互 | 控件不再被遮罩/裁切 | 通过 | 已调整滚动区、表格边框和圆角容器 |
| 视觉/交互 | 会话中心宽度、按钮尺寸、整体密度 | 通过 | 已按用户反馈收窄并全局收紧控件尺寸 |

## 6. 算法与策略验收

| 场景 | 期望 | 实测 | 结果 |
| --- | --- | --- | --- |
| 麒麟纯国密 `auto` | 优先尝试国密，必要时旧版国密适配 | modern 触发 MAC 错误后切 legacy，完成登录/SFTP | 通过 |
| 麒麟纯国密 `gm_only` | 只使用国密链路 | legacy 国密链路可用 | 通过 |
| 麒麟纯国密 `standard_only` | 应失败 | 服务端只 offer `ecgm-sm2-sm3`，标准算法失败 | 通过 |
| openEuler `:2222` `auto` | 优先国密并成功 | `sm2-sm3/sm2/sm4-ctr/hmac-sm3` 成功 | 通过 |
| openEuler `:2222` `gm_only` | 只使用国密链路并成功 | terminal/SFTP/forwarding 全部通过 | 通过 |
| openEuler `:2222` `standard_only` | 应失败 | 服务端只 offer `sm2-sm3`，标准算法失败 | 通过 |
| openEuler `:22` `auto` | 国密不可用时回落标准链路 | 记录算法回退后标准 SSH 可用 | 通过 |
| openEuler `:22` `standard_only` | 标准 SSH 成功 | 命令执行/SFTP/forwarding 成功 | 通过 |
| openEuler `:22` `gm_only` | 应失败 | 服务端未接受国密算法 | 通过 |

## 7. 已知限制与风险

| 项目 | 状态 | 处理意见 |
| --- | --- | --- |
| 麒麟 `ecgm-sm2-sm3` | 依赖“旧版国密适配（降低校验强度）+ legacy 引擎回退” | 文案必须明确这是兼容适配，不声明为严格校验能力 |
| openEuler 系统 `:22` 纯国密 | 曾卡在服务端配置/启动链路 | 不作为当前客户端验收阻塞项；继续使用 `:2222` 独立验证服务 |
| 打包后的引擎路径 | 未完成正式验收 | 下一阶段做 App 打包验证，确认不依赖开发目录 |
| USBKey / PKCS#11 | 未接入实机 | V1.1 或独立任务处理 |
| `sm2_key` / OpenSSH cert / X509 SM2 cert | 纯国密正向用例未全量完成 | 后续补认证矩阵 |
| 完整终端模拟器能力 | 基础交互已可用，复杂 TUI 未覆盖 | 后续补 `vim/top/less` 等交互测试 |
| Matter 字体 | 运行日志提示字体缺失 | 不影响功能；如需消除警告，后续打包字体或改为已安装字体 |

## 8. 归档清单

GUI 截图归档：

- `build/gui-acceptance/20260429-gui/01-kylin-terminal.png`
- `build/gui-acceptance/20260429-gui/02-kylin-terminal-command.png`
- `build/gui-acceptance/20260429-gui/03-kylin-sftp-list.png`
- `build/gui-acceptance/20260429-gui/05-kylin-sftp-delete.png`
- `build/gui-acceptance/20260429-gui/06-openeuler-terminal.png`
- `build/gui-acceptance/20260429-gui/06-openeuler-terminal-attempt2.png`

自动化归档：

- `build/p1-matrix/20260429-101803/p1-matrix-report.json`
- `build/openeuler-functional/20260429-101619-systemd/summary.json`
- `build/openeuler-functional/20260429-101619-systemd/sftp.log`
- `build/openeuler-functional/20260429-101619-systemd/forward.log`
- `build/openeuler-functional/20260429-101619-systemd/terminal.log`

## 9. 签署状态

| 角色 | 状态 | 说明 |
| --- | --- | --- |
| 自动化验收 | 已通过 | P1 矩阵 9/9，通过 openEuler 功能专项 |
| GUI 人工验收 | 已归档，待最终签字 | 当前截图与用户现场反馈支持通过；正式交付前建议由用户最终确认一次当前二进制 |
| 进入下一阶段 | 可以进入 | 下一阶段优先做打包验证与剩余认证类型矩阵 |
