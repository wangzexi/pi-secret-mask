# pi-secret-mask 🔐

**Pi 插件：在密钥到达 LLM 之前用形似的占位符替换，执行时再恢复回真实值。**

模型（缸中之脑）永远只看到长得和真实密钥一模一样的占位符。扩展维护一张 1:1 映射表，在桥接边界——模型上下文之前、bash 执行之前——进行值的交换。

```
    用户输入: "用密钥 sk-live-abc123 发个请求"
         │
         ▼
  ┌─ input 钩子 ── 真实值 → 占位符 ──┐
  │                                   │
  │  LLM 收到:  sk-liveXyZAbCdEfGhIj  │  ← 模型以为是真货
  │                                   │
  │  LLM 执行:  curl -H "Bearer sk-liveXyZAbCdEfGhIj"
  │                                   │
  ├─ tool_call(bash) ─ 占位符 → 真实值 ─┤
  │                                      │
  │  bash 实际执行:  curl -H "Bearer sk-live-abc123"   ✅
  │                                      │
  ├─ tool_result ── 真实值 → 占位符 ────┤
  │                                      │
  │  LLM 看到:  "200 OK" (看不到真实密钥) │
  └──────────────────────────────────────┘
```

## 为什么需要这个插件

编程助手可以访问你的整个工作区——`.env`、配置文件、凭据、私钥。当你问 AI 一个问题时，这些密钥可能原样发给模型提供商。

`pi-secret-mask` 在 pi 扩展层拦截：

- **密钥到达 LLM 上下文之前** → 替换成形似的占位符
- **bash 命令执行之前** → 占位符换回真实值
- **工具结果返回时** → 真实值再次被屏蔽，LLM 看不到

LLM **从未持有明文**。即使模型被攻击、幻觉、或被提示注入攻击，也没什么可泄露的——它只知道占位符。

## 工作原理

### 检测

内置常见密钥格式的正则表达式：

| 模式 | 示例 |
|---------|--------|
| OpenAI API key | `sk-proj-…` |
| Anthropic API key | `sk-ant-…` |
| GitHub PAT (v1) | `ghp_…`, `gho_…`, `ghs_…`, `ghu_…` |
| GitHub PAT (v2) | `github_pat_…` |
| AWS access key | `AKIA…`, `ASIA…` |
| Stripe live key | `sk_live_…` |
| Stripe test key | `sk_test_…` |
| Slack token | `xoxb-…`, `xoxp-…` |
| JWT | `eyJ…eyJ…` |
| 私钥 (PEM) | `-----BEGIN … PRIVATE KEY-----` |
| Google API key | `AIza…` |
| GitLab PAT | `glpat-…` |
| SendGrid key | `SG.…` |

### 占位符格式

占位符保留原始前缀，保证格式可识别：

```
sk-proj-AbCdEfGhIjKlMnOp123456  →  sk-proj-XyZABcDeFgHiJkLmN9876543210
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  →  ghp-PrKqHmZlYkWfS7626713999
AKIAAKIAIOSFODNN7EXAMPLE       →  AKIAPdBJNeKqHmZlYkWfS7626713999
```

前缀（`sk-`、`ghp_`、`AKIA` 等分隔符前部分）不变，身体部分按**相同字符类**（大写/小写/数字）随机化，长度、前缀、分隔符位置与原始值完全一致。

### 通信通道覆盖

| 钩子 | 方向 | 变换 |
|------|----------|-----------|
| `input` | 用户 → LLM | 真实值 → 占位符 🔒 |
| `tool_call(bash)` | LLM → bash | 占位符 → 真实值 🔓 |
| `tool_call(write)` | LLM → 文件写入 | 占位符 → 真实值 🔓 |
| `tool_call(edit)` | LLM → 文件编辑 | 占位符 → 真实值 🔓 |
| `tool_result` | 工具输出 → LLM | 真实值 → 占位符 🔒 |
| `user_bash` | `!` 命令输出 → LLM | 真实值 → 占位符 🔒 |
| `context` | 会话历史 → LLM | 真实值 → 占位符（静默兜底） |
| `before_provider_request` | payload → 模型 | 真实值 → 占位符（静默兜底） |

## 安装

```bash
# 从本地路径安装
pi install /path/to/pi-secret-mask
```

重启 pi 或运行 `/reload` 激活。

## 使用

插件加载后自动运行，无需配置——按正则检测密钥并实时替换。

### 命令

| 命令 | 说明 |
|---------|-------------|
| `/secret-mask status` | 显示模式数量和映射统计 |
| `/secret-mask list` | 列出所有已注册的密钥→占位符映射 |

### 示例

1. 创建一个测试 `.env` 文件：
   ```
   OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOp123456
   ```

2. 让 pi 读取它：
   ```
   > 读取 .env 文件
   ```

3. pi 返回：
   ```
   OPENAI_API_KEY=sk-proj-XyZABcDeFgHiJkLmN9876543210
   ```
   模型看到占位符，但理解结构。

4. 让模型用这个 key 发 curl 请求。扩展在 bash 执行前把占位符换回真实值——真实密钥到达 API。模型从未看到它。

### 通知

每次 mask/unmask 操作都会在 UI 显示详细信息：

```
🔒 sk-p…1550 → sk-proj-XyZABcDeFgHiJkLmN9876543210  (来自 input)
🔓 sk-proj-XyZABcDeFgHiJkLmN9876543210 → sk-p…1550  (来自 bash)
```

真实值只显示前4+后4字符，完整映射可通过 `/secret-mask list` 查看。

## 开发

```bash
git clone https://github.com/wangzexi/pi-secret-mask
cd pi-secret-mask
# 编辑 index.ts，然后测试：
pi -e ./index.ts
```

运行单元测试：

```bash
node test/core.test.js
```

## 局限

- **纯文字替换。** 如果模型把占位符存到环境变量里再通过 `$VAR` 引用，扩展无法拦截间接引用。命令必须直接包含占位符文字。
- **依赖正则模式。** 不在内置模式列表中的密钥格式会原样通过。如有需要可添加自定义模式。
- **尽力而为的脱敏。** 扩展无法防止所有可能的旁路信道（如时序、错误消息）。它是一种实用的安全措施，不是加密保证。
- **不是沙箱。** 这个插件在 pi 事件层运行。需要对 egress 进行内核级控制的话，请配合沙箱工具使用。

## License

MIT
