# pi-fake-secret 🎭

**Secret NAT——像 NAT 转换网络地址一样，Harness 替模型换密钥。**

模型只能看到假密钥，执行时 Harness 换成真的。

```
                 ┌────────────────────────────┐
                 │         Harness             │
                 │  ┌──────────────────────┐  │
用户/文件 ──fake──►│  │        model         │  │
                 │  └──────────────────────┘  │
用户/文件 ◄─restore─│                             │
                 └────────────────────────────┘
```

## 为什么

工作区里有 `.env`、配置文件、私钥。问 AI 问题时，这些密钥可能原样发给模型。

`pi-fake-secret` 在边界拦截：进去的换成假密钥，出来的还原成真的。模型只碰假的。

## 安装

```bash
pi install /path/to/pi-fake-secret
```

重启 pi 或 `/reload` 激活。

## 使用

自动运行，无需配置。

| 命令 | 说明 |
|---------|------|
| `/secret-mask status` | 映射统计 |
| `/secret-mask list` | 列出所有映射 |

通知示例：

```
🎭 造假: sk-p…2504 → sk-proj-XyZABcDeFgHiJkLmN9876543210
🎭 还原: sk-proj-XyZABcDeFgHiJkLmN9876543210 → sk-p…2504
```

## 覆盖通道

| 钩子 | 方向 | 变换 |
|------|------|------|
| `input` | 用户 → model | 真→假 🎭 |
| `tool_call(bash)` | model → 执行 | 假→真 |
| `tool_call(write)` | model → 文件 | 假→真 |
| `tool_call(edit)` | model → 编辑 | 假→真 |
| `tool_result` | 结果 → model | 真→假 🎭 |
| `user_bash` | `!` 命令 → model | 真→假 🎭 |
| `context` | 历史 → model | 真→假（静默） |
| `before_provider_request` | payload → 模型 | 真→假（静默） |

## 内置格式

OpenAI、Anthropic、GitHub PAT、AWS、Stripe、Slack、JWT、PEM 私钥、Google API、GitLab、SendGrid 等常见密钥格式。

## 开发

```bash
git clone https://github.com/wangzexi/pi-fake-secret
cd pi-fake-secret
npm test
pi -e ./index.ts
```

## License

MIT
