# LuCI Fail2ban Manager

OpenWrt LuCI 的 Fail2ban 管理页面：查看运行中的 jail、当前封禁 IP、最近 200 条封禁/解封记录，以及手动解封单个 IP。时间格式为 `2026-09-06 22:09:12`。

**这是管理工具，不是防护配置向导。** 安装、升级、卸载本插件不会写入 Fail2ban 配置、创建 jail、修改防火墙或重启 Fail2ban。只重新加载 rpcd 以注册/移除管理接口。依赖包首次安装时可能运行其自己的官方初始化脚本；已有 Fail2ban 配置由其包管理机制维护。

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
apk add /tmp/luci-app-fail2ban-manager-1.0.4-r1.apk
```

以实际产物文件名为准。不要全局关闭签名校验，不需要 `--force-overwrite`。页面位于 **服务 → Fail2ban**。如浏览器缓存旧页面，强制刷新后重新进入。

卸载：`apk del luci-app-fail2ban-manager`。不使用 `--purge`，不手动删除 Fail2ban 数据和配置。如决定不再信任本项目发布密钥，可另外移除 `/etc/apk/keys/luci-fail2ban-manager.pem`。

## 安全边界

- 使用 LuCI 登录会话和 rpcd ACL；只读账号无解封权限。
- 唯一写操作是对当前运行 jail 中一个已封禁 IP 执行解封；再次读取确认结果。
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

页面读取各 jail 当前运行策略，展示固定时长或基础时长、重复违规递增及配置的最长时长，不修改防护规则。递增策略的初始时长是基础值；已有历史的地址可能直接进入更长的封禁。

“当前封禁”的预计解封时间来自 Fail2ban 当前 ban ticket（`get <jail> banip --with-time`），包含实际递增时长，使用路由器本地时间，格式为 `2026-10-22 23:30:00`。永久封禁单独标注；旧版 Fail2ban 不支持查询或无法识别返回格式时显示“未知”，不以基础时长推算。解封由 Fail2ban 执行，页面每15秒刷新，实际执行可能有短暂延迟。

同时显示本次实际封禁时长和剩余时间；剩余时间按路由器采样时钟计算，随15秒刷新更新，不依赖访问电脑的时钟。顶部将运行状态和最后更新时间分开，标明路由器 UTC 偏移；日志和解封时间沿用路由器本地时间。更新失败时保留上次成功数据和时间，并明确标记更新失败，不能据此认定封禁仍在生效。“观察窗口内失败次数”是 Fail2ban 当前跟踪的认证失败次数，不是攻击者数量。

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
python3 -m unittest discover -s tests -p test_signing.py
```

源码可作为 OpenWrt package/feed 编译；无需重新编译整个固件。SDK 和工作流依赖参考 [OpenWrt SDK](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)、[官方 SDK Action](https://github.com/openwrt/gh-action-sdk)。

MIT 许可。与 Fail2ban/OpenWrt 官方项目无隶属关系。
