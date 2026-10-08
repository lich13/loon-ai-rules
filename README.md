# AI 路由规则

供 Loon 与 mihomo 使用的通用规则，Claude 与其他 AI 服务分别选择策略。这里不保存客户端配置、订阅地址、节点或凭据。

| 文件 | 来源与用途 |
| --- | --- |
| `rules/Claude.list` | MetaCubeX Anthropic，加上官方桌面域名及 API 入口 IP |
| `rules/AI-Meta.list` | MetaCubeX 综合 AI，移除 Claude |
| `rules/AI-Kelee.list` | 可莉 AI 中未被前两份规则覆盖的域名和兼容逻辑 |

客户端依次匹配 Claude、AI-Meta、AI-Kelee，再匹配 GitHub 等一般网站规则与直连兜底。mihomo 使用 `behavior: classical`、`format: text`；Loon 使用远程规则。规则中没有策略名称，由各客户端配置指定。

## 更新

GitHub Actions 每天北京时间 10:30 取源并校验，也可手动运行。MetaCubeX 的两个输入固定到同一提交，全部源验证成功后一次发布三份产物。下载失败、空源、关键域名缺失或未知语法会阻止更新，保留已发布版本。内容未变时不产生提交。

可莉的 Loon 规则入口按 `User-Agent` 识别客户端；生成器仅对该入口使用 Loon 请求头，取得原生文本规则。

```sh
python3 -m unittest discover -s scripts -p 'test_ai_rules.py' -v
python3 scripts/update_ai_rules.py
```

当前唯一的 Azure 域名正则转换为限定关键词与 `webpubsub.azure.com` 后缀的 `AND` 规则，与可莉的 Loon 兼容写法一致；不承诺对任意正则做无损转换。新语法须先人工审查并增加测试。

Claude 不按 Sentry、Datadog、Intercom 等共享服务的整个域名或无关 ASN 分类。官方入口 IP 来自 [Anthropic IP 文档](https://platform.claude.com/docs/en/api/ip-addresses)，桌面补充来自 [网络要求](https://code.claude.com/docs/en/desktop#network-access-requirements)。第三方网关按其域名分类，无法据此识别一次请求具体使用哪个模型。

## 来源

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：仓库许可证为 [GPL-3.0](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)，域名数据上游包括 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。
- [可莉 / luestr/ProxyResource](https://github.com/luestr/ProxyResource)：[CC BY-NC-SA 4.0](https://github.com/luestr/ProxyResource/blob/main/LICENSE)。

各产物保留来源、转换说明和许可证链接，两个来源分别输出，不将它们改标为同一种许可证。此仓库不保证服务可用性或账号状态。
