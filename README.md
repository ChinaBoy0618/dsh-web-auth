# dsh-web-auth

DSH Web 的公网鉴权门:一个跑在 DSH web 进程里的 loopback 反向代理(gate),
给经 frp/隧道暴露的 DSH Web 加 token 登录。

## 为什么需要它

- `dsh web` 只绑 `127.0.0.1`,其 `/api` 的 Host 信任栅栏把非 loopback 来源一律 403
  (防 DNS-rebinding / cross-origin),所以经 frp 隧道进来的请求全部被栅栏拦下。
- DSH 本身没有面向公网访问者的登录/密码层。
- 直接 `--trusted-host <公网>` 只是"给公网 IP 开栅栏缝",不等于认证。

本插件把栅栏和认证合并成一个正确架构:

```
公网 → frp 隧道 → 127.0.0.1:3081 (gate, token 登录) → 127.0.0.1:3080 (DSH web, Host=loopback → 栅栏放行)
```

## 行为

| 请求 | 结果 |
|---|---|
| 未登录浏览器 GET 页面 | 302 → `/__dsh-auth__/login` 登录页 |
| 未登录 `/api`、静态资源、WebSocket upgrade | `401` |
| 登录页 `POST /__dsh-auth__/login`(`token` 字段,JSON 或 urlencoded) | 成功:签 HttpOnly 会话 cookie(默认 12h,滑动续期),302 回原路径 |
| `X-DSH-Auth: <token>` 头 | 免 cookie,供 curl / 脚本 |
| `POST /__dsh-auth__/logout` | 清 cookie |
| 同源 IP 连续失败 10 次 | 限速 10 分钟 |

## token 从哪来(优先级)

1. 插件行配置 `config.token`
2. 环境变量 `DSH_WEB_AUTH_TOKEN`
3. 文件 `$DSH_HOME/web-auth-token`(默认 `~/.dsh/web-auth-token`,可用 `tokenFile` 覆盖)

找不到 token 时 gate **不启动**(fail closed,公网入口不可用),DSH 本体不受影响。

## 行配置(全部可选)

| key | 默认 | 说明 |
|---|---|---|
| `gateHost` | `127.0.0.1` | gate 绑定地址 |
| `gatePort` | `3081` | gate 监听端口(frpc 应指向这里) |
| `targetHost` | `127.0.0.1` | DSH web 地址 |
| `targetPort` | `3080` | DSH web 端口兜底值(运行时优先取 `webServer.port`) |
| `token` | — | 直接内联 token |
| `tokenFile` | `web-auth-token` | token 文件名(相对 `$DSH_HOME`)或绝对路径 |
| `sessionTtlMinutes` | `720` | 会话 cookie 有效期(分钟,滑动续期) |
| `maxFails` | `10` | 同 IP 连续失败多少次触发限速 |
| `failWindowMs` | `600000` | 限速窗口(毫秒) |

## 安装

### 方式一:从 git 仓库安装(推荐分享)

```bash
# 把本仓库地址装进指定 profile(命令透传给 pnpm,git 地址 / npm 包名 / 本地路径都认)
dsh plugin --profile web add <git 仓库地址>
```

然后在 profile 的 `package.json` 里把 `dsh-web-auth` 追加进 `dsh.profile.bundles`:

```json
"dsh": {
  "profile": {
    "bundles": [
      "@deepseek-ai/dsh-base",
      "@deepseek-ai/dsh-web-app",
      "dsh-web-auth"
    ]
  }
}
```

### 方式二:本地路径 / npm 包

1. 把包放进 profile 的 `node_modules`(`file:` 依赖 + `pnpm install`,或 `npm publish` 后按 npm 包名装)。
2. 同上,在 profile 的 `package.json` 里 `dsh.profile.bundles` 追加 `dsh-web-auth`。

### 两种方式共同的后续步骤

3. 生成 token:`openssl rand -hex 32 > ~/.dsh/web-auth-token`。
4. frpc 把 `dsh-web` 的 `localPort` 指向 gatePort(3081)。
5. 重启 `dsh web`。

零外部依赖(只用 node 内置模块)。
