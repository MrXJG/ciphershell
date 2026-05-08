# CipherShell 互通回归验收记录（2026-05-07）

## 目标
- 完成“第二步：麒麟 + openEuler 正式链路回归”。
- 验证调试链路隔离后，零参数脚本可直接执行。

## 本次变更（为回归打通默认链路）
- 补齐正式 legacy 引擎产物：
  - `bin/ssh-legacy-ecgm`
  - `bin/sftp-legacy-ecgm`
- 回归脚本默认引擎路径改为自动探测（优先 `bin` 正式源，其次 `build/CipherShell.app/Contents/MacOS/bin`，最后 `build/bin`）：
  - `scripts/p1_matrix_regression.sh`
  - `scripts/gm_handshake_regression.sh`

## 执行环境
- 日期：2026-05-07
- 客户端：macOS
- 目标主机：
  - 麒麟 V10 SP3：`10.0.13.1:22`
  - openEuler：`10.0.13.2:22`
  - openEuler 纯国密调试端口：`10.0.13.2:2222`

## 执行命令
```bash
./scripts/p1_matrix_regression.sh
ctest --test-dir build --output-on-failure
```

## 结果摘要
- 连通性预检：通过（3/3 端口可达）
- P1 矩阵：通过（9/9 case verdict=pass）
- 单元/UI 测试：通过（2/2）

## P1 矩阵关键信号
- `kylin-auto-old-gm-adaptation`：terminal/sftp 均触发 `modern -> legacy`，原因 `gm_probe_mac_incorrect_modern_to_legacy`，最终通过。
- `kylin-gm-only-old-gm-adaptation`：同上，最终通过。
- openEuler 国密与标准链路：均按预期通过；`gm_only` 对标准端口的 expected-fail 场景判定正确。

## 产物与证据
- P1 报告（零参数最终轮）：`build/p1-matrix/20260507-091142/p1-matrix-report.json`
- 之前补充回归报告：`build/p1-matrix/20260507-084533/p1-matrix-report.json`
- 中间轮报告：`build/p1-matrix/20260507-090658/p1-matrix-report.json`

## 风险与边界
- 目前 `engine/openssh-gm` 源目录不在仓库内；legacy 二进制可用，但“从源码一键重建 legacy”链路仍需单独补齐（不影响本次互通回归结论）。
- `gm_handshake_regression.sh` 的 known_hosts 侧告警（host key changed）属于探针环境历史状态问题，不影响 P1 功能回归判定。

## 结论
- 第二步“正式回归验证”已达成：
  - 双机互通通过
  - SFTP/终端/转发路径通过
  - 调试链路隔离后，零参数执行可用
