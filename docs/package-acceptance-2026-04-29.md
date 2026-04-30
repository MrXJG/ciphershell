# macOS 打包验收记录（2026-04-29）

## 1. 验收结论

本轮 macOS 打包验收结论：**功能通过，可用于当前联调环境交付验证**。

通过范围：

- 生成真实 macOS `.app` bundle：`build/gmssh_client.app`。
- 生成 DMG：`build/gmssh-client-0.1.0-Darwin.dmg`。
- `.app/Contents/MacOS/bin/` 内置 modern 与 legacy 两套 SSH/SFTP 引擎。
- 使用包内引擎完成 P1 互通矩阵，结果 9/9 通过。
- 主程序动态库路径已指向 `@executable_path/../Frameworks/...`，不再直接依赖 Homebrew Qt 绝对路径。

非阻塞警告：`macdeployqt` 阶段仍可能输出 Homebrew Qt 依赖解析提示，但打包脚本会在依赖部署后重新 ad-hoc codesign，并对 build App、DMG staging App、挂载后的 DMG App 做 `codesign --verify --deep --strict`。本轮验证未再复现 `Code Signature Invalid`。正式对外发布前仍建议补 Developer ID 签名/公证。

## 2. 交付物

| 类型 | 路径 | 状态 |
| --- | --- | --- |
| App bundle | `build/gmssh_client.app` | 已生成 |
| DMG | `build/gmssh-client-0.1.0-Darwin.dmg` | 已生成 |
| 打包验收报告 | `build/package-verification/20260429-152704/package-report.json` | `verdict=pass` |
| 包内 P1 矩阵报告 | `build/package-verification/20260429-152704/p1-matrix-report.json` | 9/9 通过 |
| DMG 生成日志 | `build/package-verification/20260429-152704/hdiutil-create.log` | 自定义 `hdiutil` 生成，绕开 CPack 二次改签问题 |
| macdeployqt 日志 | `build/package-verification/20260429-152704/macdeployqt.log` | 有非致命依赖提示，后续 codesign 验证通过 |
| DMG 挂载检查 | `hdiutil attach` + `find */Contents/MacOS/bin/*` | 镜像内四个引擎均为 arm64 Mach-O 可执行文件 |
| Applications 拖拽入口 | DMG 根目录 `Applications -> /Applications` | 已包含，Finder 可拖拽安装 |
| App 图标 | `build/gmssh_client.app/Contents/Resources/gmssh.icns` | 已替换为 `playground-image-3.png` 生成的透明背景 `.icns`，`Info.plist` 已配置 `CFBundleIconFile=gmssh.icns` |
| 签名检查 | `codesign --verify --deep --strict` | build App、DMG staging App、挂载后的 DMG App 均通过 |
| DMG 图标检查 | `hdiutil attach` + `PlistBuddy CFBundleIconFile` | 镜像内 App 已包含 `gmssh.icns` |

DMG SHA256：

```text
c9e06d71166edeb1ee1282562b76e6b2b2265d6b2601d0f5e42259f3b1ddfd67  build/gmssh-client-0.1.0-Darwin.dmg
```

## 3. 包内引擎检查

| 引擎 | 包内路径 | SHA256 | 状态 |
| --- | --- | --- | --- |
| modern SSH | `build/gmssh_client.app/Contents/MacOS/bin/ssh` | `375caf8f7c29fcf939ff86acd130d4f01b6e84dce68651e1b5fe1168845dcf48` | 可执行 |
| modern SFTP | `build/gmssh_client.app/Contents/MacOS/bin/sftp` | `4f89a66787c28ae7277b44f2093ee54be5d672c3c207cd2b0b84faa599271825` | 可执行 |
| legacy SSH | `build/gmssh_client.app/Contents/MacOS/bin/ssh-legacy-ecgm` | `4e4b8386042445658ae7808b34a850d32242c9f3d215c50475a7bad8abf5ecfd` | 可执行 |
| legacy SFTP | `build/gmssh_client.app/Contents/MacOS/bin/sftp-legacy-ecgm` | `5c7cdf5b68375a0564bc3d03614cd1b04078f8f6821d66fe83c1a5d36db12314` | 可执行 |

hdiutil staging App 也包含同样的四个包内引擎：

- `ssh`
- `sftp`
- `ssh-legacy-ecgm`
- `sftp-legacy-ecgm`

## 4. 国密算法能力检查

| 检查项 | 结果 |
| --- | --- |
| modern `ecgm-sm2-sm3` | 通过 |
| modern `sm2-sm3` | 通过 |
| modern `sm2` hostkey | 通过 |
| modern `sm4-ctr` | 通过 |
| modern `hmac-sm3` | 通过 |
| legacy `ecgm-sm2-sm3` | 通过 |
| legacy `sm2` hostkey | 通过 |
| legacy `sm4-ctr` | 通过 |
| legacy `hmac-sm3` | 通过 |

## 5. 包内引擎 P1 矩阵

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

## 6. 打包脚本

新增脚本：`scripts/package_macos_app.sh`。

脚本执行内容：

- 重新配置和构建 `build/gmssh_client.app`。
- 运行 `macdeployqt` 部署 Qt 依赖。
- 检查包内四个引擎是否存在且可执行。
- 检查 modern/legacy 引擎的国密算法能力。
- 扫描 `.app/Contents/MacOS` 下可执行文件，确认不包含当前开发目录路径。
- 使用包内引擎执行 P1 矩阵。
- 对 `.app` 执行 ad-hoc codesign，并用 `codesign --verify --deep --strict` 验证。
- 在 DMG 根目录创建 `Applications -> /Applications` 拖拽安装入口。
- 使用 `hdiutil create` 从已签名 staging App 生成 DMG，避免 CPack 二次修改二进制导致签名失效。
- 输出 `package-report.json`。

默认执行：

```bash
scripts/package_macos_app.sh
```

可选跳过远端 P1：

```bash
GMSSH_RUN_PACKAGE_P1=0 scripts/package_macos_app.sh
```

## 7. 已知风险

| 风险 | 当前影响 | 后续处理 |
| --- | --- | --- |
| `macdeployqt` 依赖解析提示 | 脚本后续重新签名并验证，功能验收未受影响 | 后续可精简 Qt 插件/依赖部署范围 |
| 未签名/未公证 | 只适合内部测试交付，外部机器可能受 Gatekeeper 影响 | 正式发布前增加 Developer ID 签名和 notarization |
| 当前验收依赖本机保存凭据和测试网络 | 换机器后需重新导入会话/凭据并重跑验收 | 发布说明中明确测试前置条件 |
| DMG 名称仍是默认英文名 | 不影响功能，但交付识别度一般 | 发布前改为中文/产品化命名 |
