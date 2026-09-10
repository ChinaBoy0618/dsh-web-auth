import { readFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
//#region lib/types/index.js
/**
 * dsh-web-auth — DSH Web 公网鉴权门（token 登录 + cookie 会话）。
 *
 * 背景：`dsh web` 只绑定 127.0.0.1，其 /api 的 Host 信任栅栏（防
 * DNS-rebinding/cross-origin）意味着经 frp 隧道进来的请求 Host 是
 * 公网地址，全部被 403。DSH 本身没有面向公网访问者的登录层。
 *
 * 本插件在 DSH Web 进程内再起一个只绑 loopback 的 HTTP 服务
 * （默认 127.0.0.1:3081，"gate"），作为 frp 隧道的唯一入口：
 *
 *   公网 → frp → 127.0.0.1:3081 (gate, 校验 token/cookie)
 *          → 127.0.0.1:3080 (dsh web, Host 头改写为 loopback → 栅栏放行)
 *
 * 行为：
 * - 未登录 GET（浏览器导航）→ 302 到登录页 /__dsh-auth__/login
 * - 未登录 /api、静态资源、WebSocket upgrade → 401
 * - 登录页：POST /__dsh-auth__/login，body 支持 JSON 或 urlencoded，
 *   字段名 token；成功签发 HttpOnly 会话 cookie（滑动续期），302 回原路径
 * - 正确 token 也可走请求头 X-DSH-Auth（供 curl/脚本）
 * - 连续失败超限后按来源 IP 限速（防暴力）
 * - token 解析顺序：行配置 token → 环境变量 DSH_WEB_AUTH_TOKEN
 *   → 文件 $DSH_HOME/web-auth-token（可用 tokenFile 覆盖，支持绝对路径）
 * - 监听端口被占用等绑定失败时只告警、不拖垮 DSH 进程
 * - 零外部依赖：只用 node 内置模块
 *
 * @module dsh-web-auth
 */
/** Stable Cordis plugin name. */
const name = "web-auth";
/** Services required before the gate can resolve the DSH web port. */
const inject = ["webServer"];
const LOGIN_PATH = "/__dsh-auth__/login";
const LOGOUT_PATH = "/__dsh-auth__/logout";
const SESSION_COOKIE = "dsh_auth";
const TOKEN_HEADER = "x-dsh-auth";
/** Hop-by-hop 头：转发两侧都剥掉，另剥 host（改写）/cookie/本插件 token 头。 */
const HOP_BY_HOP = new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"upgrade"
]);
/** 默认配置（行配置可覆盖）。无 Config 导出：裸插件形态，手动归一化。 */
const DEFAULTS = {
	gateHost: "127.0.0.1",
	gatePort: 3081,
	targetHost: "127.0.0.1",
	targetPort: 3080,
	token: void 0,
	tokenFile: "web-auth-token",
	sessionTtlMinutes: 720,
	maxFails: 10,
	failWindowMs: 600000
};
/** $DSH_HOME 约定（同 @deepseek-ai/dsh-home-paths 的解析，避免引入依赖）。 */
function dshHome() {
	return process.env.DSH_HOME ?? join(homedir(), ".dsh");
}
/** 解析 token：行配置 → 环境变量 → 文件（相对路径相对 $DSH_HOME）。 */
function resolveToken(cfg) {
	if (typeof cfg.token === "string" && cfg.token.trim() !== "") return cfg.token.trim();
	const fromEnv = process.env.DSH_WEB_AUTH_TOKEN;
	if (fromEnv !== void 0 && fromEnv.trim() !== "") return fromEnv.trim();
	const file = isAbsolute(cfg.tokenFile) ? cfg.tokenFile : join(dshHome(), cfg.tokenFile);
	try {
		const raw = readFileSync(file, "utf8");
		return raw.trim() === "" ? void 0 : raw.trim();
	} catch {
		return void 0;
	}
}
/** 恒定时间字符串比较（长度不同先对等长缓冲比较再返回 false）。 */
function safeEquals(a, b) {
	const ba = Buffer.from(a, "utf8");
	const bb = Buffer.from(b, "utf8");
	if (ba.length !== bb.length) {
		timingSafeEqual(ba, ba);
		return false;
	}
	return timingSafeEqual(ba, bb);
}
/** 从请求里取会话 cookie 值。 */
function cookieValue(req, cookieName) {
	const raw = req.headers.cookie;
	if (typeof raw !== "string" || raw === "") return void 0;
	for (const part of raw.split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		if (part.slice(0, idx).trim() === cookieName) return part.slice(idx + 1).trim();
	}
	return void 0;
}
/** next 防开放重定向：只接受站内相对路径。 */
function safeNext(value) {
	if (typeof value !== "string") return "/";
	if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.includes("//")) return "/";
	if (value.length > 2048) return "/";
	return value;
}
function loginPage(error) {
	return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>DSH 访问认证</title>
<style>
:root{color-scheme:dark light}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:#101318;color:#e6e9ef}
form{width:min(360px,90vw);background:#1a1f29;border:1px solid #2c3442;border-radius:12px;padding:28px 24px;box-shadow:0 12px 40px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 4px}
p{font-size:13px;color:#9aa4b5;margin:0 0 18px;line-height:1.5}
label{display:block;font-size:12px;color:#9aa4b5;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:14px;border-radius:8px;border:1px solid #39435a;background:#0f1218;color:inherit;outline:none}
input:focus{border-color:#5b8cff}
button{width:100%;margin-top:16px;padding:10px;font-size:14px;border:0;border-radius:8px;background:#3b6df0;color:#fff;cursor:pointer}
button:hover{background:#2f5cd0}
.err{display:none;font-size:13px;color:#ff7a7a;margin:10px 0 0}
.err.show{display:block}
code{font-size:12px;color:#9aa4b5}
</style>
</head>
<body>
<form method="post" action="${LOGIN_PATH}">
<h1>DSH 访问认证</h1>
<p>此 DSH Web 实例经 frp 隧道暴露到公网，输入访问 token 后进入。<br/>
Access this DSH Web instance with your token.</p>
<label for="token">访问 token / Access token</label>
<input id="token" name="token" type="password" autocomplete="off" autofocus required />
<p class="err" id="err">token 不正确，请重试。/ Wrong token.</p>
<button type="submit">进入 / Enter</button>
</form>
<script>
const err = document.getElementById("err");
if (new URLSearchParams(location.search).get("error")) err.classList.add("show");
document.getElementById("token").addEventListener("keydown", (e) => {
	if (e.key === "Enter") e.target.form.submit();
});
</script>
</body>
</html>
`;
}
/**
 * 创建鉴权门 HTTP 服务（请求 + WebSocket upgrade 透传）。
 * @param opts - targetHost/targetPort：DSH web 实际地址；token；会话与限速参数；log 输出。
 * @returns 尚未监听的 node:http Server。
 */
function createGate(opts) {
	const {
		targetHost,
		targetPort,
		token,
		sessionTtlMs,
		maxFails,
		failWindowMs,
		log
	} = opts;
	const sessions = new Map(); // cookie 值 → 到期时间戳
	const attempts = new Map(); // 来源 IP → { count, resetAt, lockedUntil }
	const targetAuthority = `${targetHost}:${String(targetPort)}`;
	function authorized(req) {
		const headerToken = req.headers[TOKEN_HEADER];
		if (typeof headerToken === "string" && headerToken !== "") return safeEquals(headerToken, token);
		const id = cookieValue(req, SESSION_COOKIE);
		if (id === void 0 || id === "") return false;
		const expiry = sessions.get(id);
		if (expiry === void 0) return false;
		if (Date.now() > expiry) {
			sessions.delete(id);
			return false;
		}
		sessions.set(id, Date.now() + sessionTtlMs); // 滑动续期
		return true;
	}
	function isLocked(ip) {
		const rec = attempts.get(ip);
		if (rec === void 0) return false;
		if (rec.lockedUntil !== void 0 && Date.now() < rec.lockedUntil) return true;
		if (Date.now() >= rec.resetAt) attempts.delete(ip);
		return false;
	}
	function recordFailure(ip) {
		const now = Date.now();
		const rec = attempts.get(ip);
		if (rec === void 0 || now >= rec.resetAt) attempts.set(ip, {
			count: 1,
			resetAt: now + failWindowMs,
			lockedUntil: void 0
		});
		else {
			rec.count += 1;
			if (rec.count >= maxFails) {
				rec.lockedUntil = now + failWindowMs;
				rec.count = 0;
				log(`dsh web-auth: 来源 ${ip} 连续失败 ${String(maxFails)} 次，限速 ${String(Math.round(failWindowMs / 60000))} 分钟`);
			}
		}
	}
	function clearFailures(ip) {
		attempts.delete(ip);
	}
	/** 剥掉逐跳/改写类头；host 指向 DSH web（loopback → 信任栅栏放行）。 */
	function cleanRequestHeaders(req) {
		const out = {};
		for (const [key, value] of Object.entries(req.headers)) {
			const lower = key.toLowerCase();
			if (HOP_BY_HOP.has(lower) || lower === "host" || lower === "transfer-encoding") continue;
			if (lower === "cookie" || lower === TOKEN_HEADER) continue;
			if (value === void 0) continue;
			out[lower] = Array.isArray(value) ? value.join(", ") : value;
		}
		out["host"] = targetAuthority;
		// 栅栏还要求 Origin 与 Host 同源:浏览器带来的公网 Origin 必须改写成目标
		// loopback origin, 否则 /api 与 WS 全部 403。
		if (out["origin"] !== void 0) out["origin"] = `http://${targetAuthority}`;
		return out;
	}
	/** 响应头同样剥逐跳头；其余原样透传（含 set-cookie 等）。 */
	function cleanResponseHeaders(headers) {
		const out = {};
		for (const [key, value] of Object.entries(headers)) {
			const lower = key.toLowerCase();
			if (HOP_BY_HOP.has(lower) || lower === "connection") continue;
			if (value === void 0) continue;
			out[lower] = value;
		}
		return out;
	}
	function readBody(req, limit, done) {
		const chunks = [];
		let size = 0;
		req.on("data", (chunk) => {
			size += chunk.length;
			if (size > limit) {
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => done(Buffer.concat(chunks)));
		req.on("error", () => done(Buffer.alloc(0)));
	}
	/** 从 JSON 或 urlencoded 请求体取 token 字段。 */
	function extractToken(body) {
		if (body.length === 0) return void 0;
		try {
			const text = body.toString("utf8");
			if (text.trimStart().startsWith("{")) {
				const parsed = JSON.parse(text);
				if (typeof parsed?.token === "string") return parsed.token;
			}
			const urlencoded = new URLSearchParams(text);
			const value = urlencoded.get("token");
			if (typeof value === "string") return value;
		} catch {}
		return void 0;
	}
	function send(res, status, contentType, body) {
		res.writeHead(status, {
			"content-type": contentType,
			"content-length": String(Buffer.byteLength(body))
		});
		res.end(body);
	}
	function redirect(res, location, setCookie) {
		const headers = { location, "content-length": "0" };
		if (setCookie !== void 0) headers["set-cookie"] = setCookie;
		res.writeHead(302, headers);
		res.end();
	}
	function proxy(req, res) {
		const up = httpRequest({
			host: targetHost,
			port: targetPort,
			method: req.method,
			path: req.url,
			headers: cleanRequestHeaders(req)
		}, (upRes) => {
			res.writeHead(upRes.statusCode, cleanResponseHeaders(upRes.headers));
			upRes.pipe(res);
		});
		up.on("error", (error) => {
			log(`dsh web-auth: upstream error: ${error instanceof Error ? error.message : String(error)}`);
			if (!res.headersSent) send(res, 502, "text/plain; charset=utf-8", "502 bad gateway");
			else res.end();
		});
		req.on("aborted", () => up.destroy());
		req.pipe(up);
	}
	const server = createServer((req, res) => {
		let url;
		try {
			url = new URL(req.url ?? "/", "http://x");
		} catch {
			return send(res, 400, "text/plain", "bad request");
		}
		const ip = req.socket?.remoteAddress ?? "unknown";
		if (url.pathname === LOGIN_PATH && req.method === "GET") {
			if (authorized(req)) return redirect(res, "/");
			return send(res, 200, "text/html; charset=utf-8", loginPage());
		}
		if (url.pathname === LOGIN_PATH && req.method === "POST") {
			if (isLocked(ip)) return send(res, 429, "text/plain; charset=utf-8", "too many failed attempts, try later");
			return readBody(req, 65536, (body) => {
				const candidate = extractToken(body);
				if (candidate === void 0 || !safeEquals(candidate, token)) {
					recordFailure(ip);
					return send(res, 401, "application/json; charset=utf-8", JSON.stringify({
						error: "invalid token"
					}));
				}
				clearFailures(ip);
				const id = randomBytes(32).toString("hex");
				sessions.set(id, Date.now() + sessionTtlMs);
				const next = safeNext(url.searchParams.get("next"));
				redirect(res, next, `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax`);
				log(`dsh web-auth: 来源 ${ip} 登录成功`);
			});
		}
		if (url.pathname === LOGOUT_PATH && req.method === "POST") {
			const id = cookieValue(req, SESSION_COOKIE);
			if (id !== void 0) sessions.delete(id);
			redirect(res, LOGIN_PATH, `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
			return;
		}
		if (!authorized(req)) {
			const accept = req.headers.accept;
			const wantsHtml = typeof accept === "string" && /text\/html|application\/xhtml/i.test(accept);
			if (req.method === "GET" && wantsHtml) {
				redirect(res, `${LOGIN_PATH}?next=${encodeURIComponent(url.pathname + url.search)}&error=1`);
				return;
			}
			return send(res, 401, "application/json; charset=utf-8", JSON.stringify({
				error: "unauthorized",
				login: LOGIN_PATH
			}));
		}
		proxy(req, res);
	});
	server.on("upgrade", (req, socket, head) => {
		if (!authorized(req)) {
			socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
			socket.destroy();
			return;
		}
		const lines = [`${req.method} ${req.url} HTTP/1.1`];
		const raw = req.rawHeaders;
		for (let i = 0; i < raw.length; i += 2) {
			const lower = raw[i].toLowerCase();
			if (lower === "host") lines.push(`Host: ${targetAuthority}`);
			else if (lower === "origin") lines.push(`Origin: http://${targetAuthority}`);
			else lines.push(`${raw[i]}: ${raw[i + 1]}`);
		}
		const up = netConnect(targetPort, targetHost);
		const wire = () => {
			up.write(`${lines.join("\r\n")}\r\n\r\n`);
			if (head.length > 0) up.write(head);
			up.pipe(socket);
			socket.pipe(up);
		};
		up.once("connect", wire);
		up.once("error", () => socket.destroy());
		socket.once("error", () => up.destroy());
	});
	return server;
}
//#endregion
//#region lib/index.js
/**
 * 挂载鉴权门：在 DSH web 进程内以 effect 启动 gate 服务，指向 webServer 端口。
 * @param ctx - 宿主插件上下文（inject webServer）。
 * @param config - 行配置（可选），覆盖 {@link DEFAULTS}。
 */
function apply(ctx, config) {
	const cfg = {
		...DEFAULTS,
		...config
	};
	if (typeof cfg.gatePort !== "number" || !Number.isInteger(cfg.gatePort) || cfg.gatePort < 0 || cfg.gatePort > 65535) throw new Error("dsh-web-auth: gatePort 必须是 0-65535 的整数");
	if (typeof cfg.sessionTtlMinutes !== "number" || cfg.sessionTtlMinutes <= 0) throw new Error("dsh-web-auth: sessionTtlMinutes 必须是正数");
	const log = (message) => console.error(message);
	ctx.effect(() => {
		const token = resolveToken(cfg);
		if (token === void 0) {
			log("dsh web-auth: 未找到 token（行配置 token / 环境变量 DSH_WEB_AUTH_TOKEN / 文件 $DSH_HOME/" + cfg.tokenFile + "），鉴权门未启动 —— 公网入口将不可用（fail closed）");
			return;
		}
		const targetPort = ctx.webServer?.port ?? cfg.targetPort;
		const gate = createGate({
			targetHost: cfg.targetHost,
			targetPort,
			token,
			sessionTtlMs: cfg.sessionTtlMinutes * 60000,
			maxFails: cfg.maxFails,
			failWindowMs: cfg.failWindowMs,
			log
		});
		gate.on("error", (error) => {
			log(`dsh web-auth: 监听 ${cfg.gateHost}:${String(cfg.gatePort)} 失败（公网入口不可用）: ${error instanceof Error ? error.message : String(error)}`);
		});
		gate.listen(cfg.gatePort, cfg.gateHost, () => {
			log(`dsh web-auth: token 门已启动 http://${cfg.gateHost}:${String(cfg.gatePort)} → http://${cfg.targetHost}:${String(targetPort)}（登录页 ${LOGIN_PATH}）`);
		});
		return () => {
			gate.close();
		};
	}, "web-auth: token gate");
}
//#endregion
export { LOGIN_PATH, LOGOUT_PATH, apply, createGate, inject, name, resolveToken };
