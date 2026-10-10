# AI 路由规则

供 Loon 与 mihomo 使用的通用规则，Claude、Grok / Cursor 与其他 AI 服务分别选择策略。这里不保存客户端配置、订阅地址、节点或凭据。

| 文件 | 来源与用途 |
| --- | --- |
| `rules/Claude.list` | MetaCubeX Anthropic，加上官方桌面域名、API 入口 IP 及兼容域名 |
| `rules/Xai.list` | MetaCubeX xAI 与 Cursor，加上官方登录、内容和下载域名 |
| `rules/AI-Meta.list` | MetaCubeX 综合 AI，移除 Claude |
| `rules/AI-Kelee.list` | 可莉 AI 中未被 Claude、AI-Meta 覆盖的域名和兼容逻辑 |

客户端依次匹配 Claude、Xai、AI-Meta、AI-Kelee，再匹配 GitHub 等一般网站规则与直连兜底。mihomo 使用 `behavior: classical`、`format: text`；Loon 使用远程规则。规则中没有策略名称，由各客户端配置指定。

`Xai.list` 覆盖 Grok、xAI API 与 Cursor 的服务域名。综合 AI 产物保留上游的 Grok / Cursor 条目，供尚未添加 Xai 订阅的客户端继续使用；添加后由前置 Xai 规则优先匹配。Cursor 内终端、GitHub 和第三方 API 请求仍按各自目标域名分类，普通 X 社交流量不因 `grok.x.com` 而整体归入 Xai。

## 更新

GitHub Actions 每天北京时间 10:30 取源并校验，也可手动运行。MetaCubeX 的四个输入固定到同一提交，全部源验证成功后一次发布四份产物。下载失败、空源、关键域名缺失或未知语法会阻止更新，保留已发布版本。内容未变时不产生提交。

可莉的 Loon 规则入口使用 Loon `User-Agent`。CI 还通过固定版本 `curl_cffi` 使用 Safari iOS 的 TLS 参数，以处理普通 Linux curl 遇到的浏览器校验；只对可莉入口启用。HTTP 错误、校验页和不合法规则仍会停止发布。

```sh
python3 -m unittest discover -s scripts -p 'test_ai_rules.py' -v
python3 scripts/update_ai_rules.py
```

需要与 CI 相同的请求方式时，安装 `curl_cffi==0.16.3` 并添加 `--browser-tls`；常规本机运行仍只依赖 Python 标准库和 curl。

当前唯一的 Azure 域名正则转换为限定关键词与 `webpubsub.azure.com` 后缀的 `AND` 规则，与可莉的 Loon 兼容写法一致；不承诺对任意正则做无损转换。新语法须先人工审查并增加测试。

官方入口 IP 来自 [Anthropic IP 文档](https://platform.claude.com/docs/en/api/ip-addresses)，桌面补充来自 [网络要求](https://code.claude.com/docs/en/desktop#network-access-requirements)。第三方网关按其域名分类，无法据此识别一次请求具体使用哪个模型。

<a id="claude-compatibility"></a>

## Claude 兼容域名

Claude 规则另外精确匹配 `anthropic.auth0.com`、`anthropic-com.ghost.io`、`anthropic.com.cdn.cloudflare.net`，并匹配 `sentry.io`、`statsigapi.net` 及其子域名。后两项是共享服务，其他应用访问这些域名时也会使用 Claude 策略。

这些补充由独立生成器保留，不通过规则同步 App 管理。Auth0、Ghost、Cloudflare 的其他域名，以及 Datadog、Sift、Intercom、Fathom 等共享平台，不因本次兼容补充整体归入 Claude；也不按无关 ASN 分类。

## Xai 补充域名

根据 Cursor 官方[登录要求](https://prod.cursor.com/help/troubleshooting/sign-in-domains)和[网络要求](https://prod.cursor.com/docs/enterprise/network-configuration)，额外包含 `cursorvm.com`、`grokusercontent.com` 两个域名后缀，以及 `accounts.spacex.ai`、`anysphere-binaries.s3.us-east-1.amazonaws.com` 两个精确域名。后缀规则覆盖多层子域名；精确规则不扩展到其他 SpaceX 或 S3 服务。

## 来源

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：仓库许可证为 [GPL-3.0](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)，域名数据上游包括 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。
- [可莉 / luestr/ProxyResource](https://github.com/luestr/ProxyResource)：[CC BY-NC-SA 4.0](https://github.com/luestr/ProxyResource/blob/main/LICENSE)。

各产物保留来源、转换说明和许可证链接，两个来源分别输出，不将它们改标为同一种许可证。此仓库不保证服务可用性或账号状态。
