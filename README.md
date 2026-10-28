# 路由规则

供 Loon 与 mihomo 使用的通用规则（AI、高流量、GitHub、Google）。Claude/Anthropic 与 Cursor 均已并入综合 AI（AI服务）。这里不保存客户端配置、订阅地址、节点或凭据。

| 文件 | 来源与用途 |
| --- | --- |
| `rules/AI-Meta.list` | MetaCubeX 综合 AI，并入 Anthropic/Claude（桌面域名、API 入口 IP 及兼容域名）与 Cursor（含官方登录和下载域名） |
| `rules/AI-Kelee.list` | 可莉 AI 中未被 AI-Meta 覆盖的域名和兼容逻辑 |
| `rules/HighTraffic.list` | 高流量：MetaCubeX YouTube、Twitch、TikTok，加上 GitHub 下载/存储与 Google Drive/Photos 文件内容域名（见[下文](#high-traffic)） |
| `rules/GitHub.list` | MetaCubeX GitHub，去掉已进入高流量的下载域名和已在 AI-Meta 中的 Copilot 域名 |
| `rules/Google.list` | MetaCubeX Google（含 Google Play），去掉 YouTube、Drive/Photos 文件内容域名和已在 AI 产物中的域名 |

客户端依次匹配 HighTraffic（及 Telegram）、AI-Meta、AI-Kelee、GitHub、Google，再匹配其他网站规则与直连兜底。mihomo 使用 `behavior: classical`、`format: text`；Loon 使用远程规则。规则中没有策略名称，由各客户端配置指定：HighTraffic 绑定 高流量，AI-Meta / AI-Kelee / GitHub / Google 绑定 AI服务。

五份产物互不重复。高流量排在 AI 之前，因此生成器保证它不覆盖任何 AI 规则：两者重叠时条目只保留在 AI 产物中（运行输出 `high_traffic_kept_in_ai`），高流量规则若会抢先匹配 AI 域名则拒绝发布。

Grok / xAI、Claude / Anthropic 与 Cursor 均走综合 AI 产物（AI-Meta / AI-Kelee → AI服务），不再单独发布 `Cursor.list`。Cursor 内终端、GitHub 和第三方 API 请求仍按各自目标域名分类。

## 更新

GitHub Actions 每天北京时间 10:30 取源并校验，也可手动运行。MetaCubeX 的八个输入固定到同一提交，全部源验证成功后一次发布五份产物。下载失败、空源、关键域名缺失或未知语法会阻止更新，保留已发布版本。内容未变时不产生提交。

可莉的 Loon 规则入口使用 Loon `User-Agent`。CI 还通过固定版本 `curl_cffi` 使用 Safari iOS 的 TLS 参数，以处理普通 Linux curl 遇到的浏览器校验；只对可莉入口启用。HTTP 错误、校验页和不合法规则仍会停止发布。

```sh
python3 -m unittest discover -s scripts -p 'test_ai_rules.py' -v
python3 scripts/update_ai_rules.py
```

需要与 CI 相同的请求方式时，安装 `curl_cffi==0.16.3` 并添加 `--browser-tls`；常规本机运行仍只依赖 Python 标准库和 curl。

MetaCubeX Google 中的两条 Google Play 下载正则已被已发布的 `xn--ngstr-lra8j.com`、`googlevideo.com` 后缀覆盖，生成时省略；其他新正则会阻止发布。单段后缀（如 `youtube`、`google`）只接受已审查的 Google 品牌顶级域名。

当前唯一的 Azure 域名正则转换为限定关键词与 `webpubsub.azure.com` 后缀的 `AND` 规则，与可莉的 Loon 兼容写法一致；不承诺对任意正则做无损转换。新语法须先人工审查并增加测试。

官方入口 IP 来自 [Anthropic IP 文档](https://platform.claude.com/docs/en/api/ip-addresses)，桌面补充来自 [网络要求](https://code.claude.com/docs/en/desktop#network-access-requirements)。第三方网关按其域名分类，无法据此识别一次请求具体使用哪个模型。

<a id="claude-compatibility"></a>

## Claude 兼容域名（并入 AI-Meta）

AI-Meta 另外精确匹配 `anthropic.auth0.com`、`anthropic-com.ghost.io`、`anthropic.com.cdn.cloudflare.net`，并匹配 `sentry.io`、`statsigapi.net` 及其子域名。后两项是共享服务，其他应用访问这些域名时也会使用 AI服务 策略。

这些补充由独立生成器保留，不通过规则同步 App 管理。Auth0、Ghost、Cloudflare 的其他域名，以及 Datadog、Sift、Intercom、Fathom 等共享平台，不因本次兼容补充整体归入 AI；也不按无关 ASN 分类。

## Cursor 补充域名（并入 AI-Meta）

根据 Cursor 官方[登录要求](https://prod.cursor.com/help/troubleshooting/sign-in-domains)和[网络要求](https://prod.cursor.com/docs/enterprise/network-configuration)，AI-Meta 额外包含 `cursorvm.com` 域名后缀，以及 `anysphere-binaries.s3.us-east-1.amazonaws.com` 精确下载域名。后缀规则覆盖多层子域名；精确规则不扩展到其他 S3 服务。

<a id="high-traffic"></a>

## 高流量（HighTraffic）

- 视频：MetaCubeX `youtube`、`twitch`、`tiktok` 全部规则（含 `googlevideo.com`、`ytimg.com`、`yt3.googleusercontent.com` 等）。
- GitHub 下载与存储：`objects` / `release-assets` / `raw` / `media` / `github-releases` / `pkg-containers.githubusercontent.com`、`codeload.github.com`、`ghcr.io`，以及 MetaCubeX `github` 中精确列出的 S3（`github-production-*`、`github-cloud`）与 Actions 产物存储（`productionresultssa*.blob.core.windows.net`）。不使用 `amazonaws.com`、`windows.net` 等共享后缀。
- Google Drive 文件内容：`drive.usercontent.google.com`、`docs.googleusercontent.com`，以及同时满足关键词 `-docs` 与 `googleusercontent.com` 后缀的下载节点（`doc-*-docs.googleusercontent.com`）。
- Google Photos 文件内容：`photos.fife.usercontent.google.com`、`video-downloads.googleusercontent.com`、`lh3`–`lh6.googleusercontent.com`。`lh*` 也承载头像等 Google 图片，因此这些图片同样走 高流量。

`drive.google.com`、`photos.google.com` 网页、账号登录，以及经 `www.googleapis.com` / `photoslibrary.googleapis.com` 的上传与 API 请求无法按域名与普通 Google 请求区分，留在 Google.list（AI服务）。`raw.githubusercontent.com` 归入高流量，会影响通过它下载订阅或规则的请求。


- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：仓库许可证为 [GPL-3.0](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)，域名数据上游包括 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。
- [可莉 / luestr/ProxyResource](https://github.com/luestr/ProxyResource)：[CC BY-NC-SA 4.0](https://github.com/luestr/ProxyResource/blob/main/LICENSE)。

各产物保留来源、转换说明和许可证链接，可莉与 MetaCubeX 来源分别输出，不将它们改标为同一种许可证。此仓库不保证服务可用性或账号状态。
