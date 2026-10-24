# LuCI Fail2ban Manager

OpenWrt LuCI 的 Fail2ban 管理页面：查看运行中的 jail、当前封禁 IP、最近 200 条记录，按服务编辑防护策略，手动延长或解封单个 IP。时间格式为 `2026-09-06 22:09:12`。

**安装和升级不更改现有防护策略。** 软件包生命周期只重新加载 rpcd，不创建 jail、不修改防火墙、不重启 Fail2ban。只有有写权限的管理员在弹窗中明确确认修改时，才写入下述专用配置并对所选 jail 热加载。依赖包首次安装时可能运行其自己的官方初始化脚本；已有 Fail2ban 配置由其包管理机制维护。

## 安装条件

- 本次 Actions 使用官方 OpenWrt 25.12.5 SDK，输出 APK v3 包。
- 插件只有脚本和资源，包架构为 `noarch`；仍需匹配 OpenWrt/LuCI/API 和依赖版本，不能据此认为兼容所有固件。
- 依赖 `luci-base`、`rpcd`、`fail2ban`、`python3-light`、`python3-codecs`，由软件包管理器解析。
- Fail2ban 应已配置并运行。没有运行中的 jail 时，页面不会自动创建防护规则。
- OPKG 固件不能安装此 APK；需使用对应旧版 SDK 另行构建 IPK。当前流水线不发布 IPK。

## 获取和验证

正式版本在仓库 **Releases** 下载，公开发布后安装者无需 GitHub 登录。也可打开 **Actions → Build OpenWrt APK → 成功的运行 → Artifacts**，下载 `luci-app-fail2ban-manager-openwrt-25.12`。解压后包含 APK、公钥、校验文件和说明。只有成功构建后的产物才是安装包，源代码 ZIP 不能直接安装。

1. 确认下载来自本仓库的正确构建/提交。
2. 在下载目录执行 `sha256sum -c SHA256SUMS`。校验文件来自同一下载，只能检查传输损坏，不能独立证明发布者身份。
3. 通过可信渠道核对公钥指纹；`PUBLIC_KEY_SHA256` 是公钥 DER 的 SHA-256。不要盲目信任别人附带的公钥。
4. 将经过核验的公钥和 APK 传到路由器 `/tmp`，再执行：

```sh
mkdir -p /etc/apk/keys
cp /tmp/luci-fail2ban-manager.pem /etc/apk/keys/luci-fail2ban-manager.pem
apk add /tmp/luci-app-fail2ban-manager-1.0.5-r1.apk
```

以实际产物文件名为准。不要全局关闭签名校验，不需要 `--force-overwrite`。页面位于 **服务 → Fail2ban**。如浏览器缓存旧页面，强制刷新后重新进入。

卸载：`apk del luci-app-fail2ban-manager`。不使用 `--purge`，不手动删除 Fail2ban 数据和配置。如决定不再信任本项目发布密钥，可另外移除 `/etc/apk/keys/luci-fail2ban-manager.pem`。

## 安全边界

- 使用 LuCI 登录会话和 rpcd ACL；只读账号不能改策略、延长或解封。
- 写操作仅包括活动 jail 的五项数值/开关策略，以及单个当前封禁 IP 的延长和解封；不能创建 jail、传入 shell、编辑过滤器、动作命令或任意文件。
- jail 从 Fail2ban 运行实例发现，不接受任意 shell 命令；IP 使用标准库严格校验，支持 IPv4/IPv6，不接受网段、接口后缀或命令参数。
- 使用 Fail2ban 本地 Unix socket，没有新增网络监听端口。socket 本身只应由可信管理员访问。
- 手动解封写入 `authpriv.notice` 系统日志。记录保留时间取决于已有日志配置，本插件不建立独立持久化审计库。
- 最近记录是有界日志视图，不是完整历史：每个文件最多读取末尾 256 KiB，最多 8 个自定义日志文件，logread 最多取最近 1000 行且输出限制 256 KiB。截断和不可用时有提示。

## 日志和自定义路径

默认 socket 为 `/var/run/fail2ban/fail2ban.sock`。自动读取 Fail2ban 的 `logtarget`；文件目标读取当前文件与 `.1`，SYSLOG 目标读取 OpenWrt `logread`，以及 system 的 `log_file`（如有）及 `.old`、`.1`。手动解封审计来自系统日志。压缩归档和 journal-only 配置不支持。

如路径特殊，管理员可自行创建仅管理员可写的 `/etc/fail2ban-manager.json`。此文件不随安装包提供、不会被覆盖，也不向 RPC 客户端开放路径选择接口：

```json
{
  "socket": "/var/run/fail2ban/fail2ban.sock",
  "log_files": ["/var/log/fail2ban.log.1", "/var/log/fail2ban.log", "/tmp/system.log"]
}
```

`log_files` 按旧到新排列，覆盖默认日志源。填写后不会自动补充 logread；需要审计记录时将已有系统日志文件也列入。不建议把普通共享文件作为日志源。

时间保留日志原本的本地时间，只规范显示格式，不换算时区。无法识别的时间显示为空，不伪造日期。支持 OpenWrt 年份齐全的 syslog 时间和 Fail2ban 的 ISO 风格文件时间。

## 封禁策略和解封时间

页面读取各 jail 当前运行策略，展示固定时长或基础时长、重复违规递增及配置的最长时长。基础时长不是对每个 IP 的首次时长保证；已有历史的地址可能直接进入更长的封禁。

“当前封禁”的预计解封时间来自 Fail2ban 当前 ban ticket（`get <jail> banip --with-time`），包含实际递增时长，使用路由器本地时间，格式为 `2026-10-22 23:30:00`。永久封禁单独标注；旧版 Fail2ban 不支持查询或无法识别返回格式时显示“未知”，不以基础时长推算。解封由 Fail2ban 执行，页面每15秒刷新，实际执行可能有短暂延迟。

同时显示本次实际封禁时长和剩余时间；剩余时间按路由器采样时钟计算，随15秒刷新更新，不依赖访问电脑的时钟。顶部将运行状态和最后更新时间分开，标明路由器 UTC 偏移；日志和解封时间沿用路由器本地时间。更新失败时保留上次成功数据和时间，并明确标记更新失败，不能据此认定封禁仍在生效。“失败次数”是 Fail2ban 当前观察窗口内跟踪的认证失败次数，不是攻击者数量。

## 策略设置与手动延长

- “设置”弹窗只允许观察时间、失败次数、基础封禁时长、递增开关、最长封禁时长。仅写 `/etc/fail2ban/jail.d/zz-luci-manager.local` 的目标 jail，保留原配置、其他 jail 及动作；配置测试通过后只热加载目标 jail。发生失败会回退，回退失败单独报警。并发修改使用文件锁及旧值比较，不静默覆盖别人的更新。
- “延长封禁”从当前解封时间追加，不从当前时间重新计时，不受自动递增的7天上限约束。为避免溢出，单次追加和累计本次时长有3650天安全上限。永久封禁、已经解封及已变化的记录不能追加。不会先解封再封禁，也不会临时修改全局 bantime。
- 手动延长使用 Fail2ban 1.1 的 Python action 和受锁保护的 ticket。首次使用时将专用辅助模块保存到 `/etc/fail2ban/action.d/luci-manager.py`，在上述专用覆盖配置中通过 `%(known/action)s` 保留原动作并追加辅助动作。它不执行防火墙命令；其他 IP 的封禁仍完全由原动作处理。辅助模块及覆盖配置不归 APK 所有，卸载界面后仍保留有效配置，避免 Fail2ban 引用消失的脚本。
- 手动到期时间随原 Fail2ban 数据库存储，辅助模块在服务启动时恢复手动记录，避免被自动上限截短。路由器使用内存数据库时，整机重启仍会丢失数据；本插件不更改数据库存储位置和历史保留配置。
- 单 IP 延长目前按 Fail2ban 1.1 ticket 结构测试并做兼容检查；不支持的结构会拒绝操作，不以重封或全局设置绕过。输入参数和数值边界在后端再次验证。日志记录策略保存、手动延长和解封。
- 自定义 socket 仍可查看和解封，但策略与延长操作仅支持默认 OpenWrt 实例，避免把配置写入错误的服务实例。

## GitHub Actions 与签名

推送 `main` 和拉取请求先执行测试；推送 `v*` 标签或手动运行工作流时，测试通过后使用官方 SDK 镜像和固定提交的 `openwrt/gh-action-sdk` 构建入口。构建容器对 SDK 的 `mkpkg` 规则应用一个受格式检查保护的补丁，让启用签名时在创建 APK 的同时签名，而不是对未签名输入追加签名。SDK 格式发生变化则停止构建，不静默继续。

依赖编译前先检查密钥对，并用小包验证正确公钥通过、无公钥/错误公钥/截断包/未签名包均被拒绝。真实 APK 构建完成后再次进行严格验签及负向测试，并检查实际架构为 `noarch`。不会使用跳过信任检查的安装或验签选项。结果随包提供为 `signing-verification.json`，包含包和公钥指纹。

只有这些检查通过后，才上传本插件 APK 和公钥，不上传依赖包、私钥或路由器配置。标签构建成功后自动发布 Release，只有发布 job 具有仓库写权限。

首次试构建无需 Secrets，会生成仅本次运行使用的签名密钥并在结束时删除。**这种情况下每次构建的公钥不同**，不能把它当成稳定更新源。

正式长期发布前，请管理员自行生成并妥善保管 P-256 签名私钥，将 PEM 内容保存为仓库 Actions Secret **`APK_SIGNING_KEY`**。私钥不能提交到仓库或分享给安装者：

```sh
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl pkey -in private-key.pem -pubout -out luci-fail2ban-manager.pem
```

使用固定 Secret 后公钥保持稳定，发布者应另行公布可信指纹。拉取请求构建不使用发布私钥，仅使用一次性密钥。当前产物通过 Actions 下载，不自动改写软件源。

## 开发

```sh
python3 test_backend.py
node test_frontend.cjs
python3 tests/check_package.py
python3 -m unittest discover -s tests -p test_control.py
python3 -m unittest discover -s tests -p test_signing.py
```

源码可作为 OpenWrt package/feed 编译；无需重新编译整个固件。SDK 和工作流依赖参考 [OpenWrt SDK](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)、[官方 SDK Action](https://github.com/openwrt/gh-action-sdk)。

MIT 许可。与 Fail2ban/OpenWrt 官方项目无隶属关系。
