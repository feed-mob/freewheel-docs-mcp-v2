import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";

// ── Config ──────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3000");
const HOST = process.env.HOST || "0.0.0.0";
const DB_PATH = process.env.DB_PATH || "data/db/docs.sqlite";
const AUTH_MODE = process.env.AUTH_MODE || "none";
const BASE_URL = process.env.BASE_URL || "";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || "feedmob.com";
const TOKEN_SECRET = process.env.TOKEN_SECRET || randomBytes(32).toString("hex");

const ACCESS_TOKEN_TTL = 24 * 60 * 60;       // 24h in seconds
const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60;  // 30d in seconds
const DEVICE_CODE_TTL = 15 * 60;              // 15min in seconds
const DEVICE_CODE_POLL_INTERVAL = 5;          // 5s

const db = new DatabaseSync(DB_PATH, { readOnly: true });

// ── In-memory stores ────────────────────────────────────────────────
// session cookies (legacy compat)
const sessions = new Map<string, { email: string; expires: number }>();
// refresh tokens: token -> { clientId, email, expires }
const refreshTokens = new Map<string, { clientId: string; email: string; expires: number }>();
// authorization codes: code -> { clientId, email, redirectUri, codeChallenge, codeChallengeMethod, expires }
const authCodes = new Map<string, {
  clientId: string; email: string; redirectUri: string;
  codeChallenge?: string; codeChallengeMethod?: string; expires: number;
}>();
// device codes: device_code -> { clientId, userCode, email, status, expires }
const deviceCodes = new Map<string, {
  clientId: string; userCode: string; email: string | null;
  status: "pending" | "authorized" | "denied"; expires: number;
}>();
// registered clients: clientId -> { clientId, clientSecret?, clientName, redirectUris, grantTypes }
const clients = new Map<string, {
  clientId: string; clientSecret?: string; clientName: string;
  redirectUris: string[]; grantTypes: string[];
}>();

// ── Token signing (HMAC-SHA256 JWT-like) ────────────────────────────
function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlEncode(obj: object): string {
  return base64url(Buffer.from(JSON.stringify(obj)));
}

function signToken(payload: object): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now };
  const signingInput = `${base64urlEncode(header)}.${base64urlEncode(fullPayload)}`;
  const sig = createHmac("sha256", TOKEN_SECRET).update(signingInput).digest();
  return `${signingInput}.${base64url(sig)}`;
}

function verifyToken(token: string): object | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const signingInput = `${parts[0]}.${parts[1]}`;
  const expected = createHmac("sha256", TOKEN_SECRET).update(signingInput).digest();
  const actual = Buffer.from(parts[2].replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// ── Helpers ─────────────────────────────────────────────────────────
function parseCookies(h: string | undefined): Record<string, string> {
  const c: Record<string, string> = {};
  if (!h) return c;
  for (const p of h.split(";")) {
    const [k, ...v] = p.trim().split("=");
    if (k) c[k.trim()] = v.join("=").trim();
  }
  return c;
}

function sendJson(res: ServerResponse, status: number, body: object) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendRedirect(res: ServerResponse, url: string) {
  res.writeHead(302, { Location: url });
  res.end();
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
  });
}

function sha256(input: string): Buffer {
  const { createHash } = require("node:crypto");
  return createHash("sha256").update(input).digest();
}

function generateUserCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += "-";
    code += chars[randomBytes(1)[0] % chars.length];
  }
  return code;
}

function extractBearer(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

function authenticateToken(req: IncomingMessage): { email: string } | null {
  // Try Bearer token first
  const bearer = extractBearer(req);
  if (bearer) {
    const payload = verifyToken(bearer) as { email?: string } | null;
    if (payload?.email) return { email: payload.email };
  }
  // Fallback to cookie
  if (AUTH_MODE === "oauth" || AUTH_MODE === "cookie") {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies["sid"];
    if (sid) {
      const session = sessions.get(sid);
      if (session && session.expires > Date.now()) return { email: session.email };
    }
  }
  return null;
}

// ── MCP Server ──────────────────────────────────────────────────────
function createMcpServer() {
  const server = new McpServer({ name: "freewheel-docs", version: "2.0.0" });

  server.tool(
    "search_docs",
    "Search FreeWheel knowledge hub docs (FTS5 full-text search)",
    { query: z.string().describe("Search query"), limit: z.number().optional().default(5) },
    async ({ query, limit }) => {
      const rows = db.prepare(
        `SELECT p.page_id, p.title, p.url, p.file,
                snippet(pages_fts, 1, '>>>', '<<<', '...', 40) AS snippet, rank
         FROM pages_fts fts JOIN pages p ON fts.rowid = p.id
         WHERE pages_fts MATCH ? ORDER BY rank LIMIT ?`
      ).all(query, limit);
      return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
    }
  );

  server.tool(
    "get_page",
    "Get full content of a doc page by page_id",
    { page_id: z.string().describe("Page ID (numeric, from index.json)") },
    async ({ page_id }) => {
      const row = db.prepare(
        "SELECT page_id, title, url, file, content FROM pages WHERE page_id = ?"
      ).get(page_id);
      if (!row) return { content: [{ type: "text", text: `Page ${page_id} not found` }] };
      return { content: [{ type: "text", text: JSON.stringify(row, null, 2) }] };
    }
  );

  return server;
}

// ── Discovery Endpoint ──────────────────────────────────────────────
function getMetadata() {
  return {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    device_authorization_endpoint: `${BASE_URL}/device/code`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: ["openid", "email", "profile"],
    subject_types_supported: ["public"],
    introspection_endpoint: `${BASE_URL}/introspect`,
  };
}

// ── HTTP Server ─────────────────────────────────────────────────────
const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);
  const path = url.pathname;

  // ── Health (always open) ──
  if (path === "/health" && req.method === "GET") {
    sendJson(res, 200, { ok: true });
    return;
  }

  // ── Discovery ──
  if (path === "/.well-known/oauth-authorization-server" && req.method === "GET") {
    sendJson(res, 200, getMetadata());
    return;
  }

  // ── Dynamic Client Registration (RFC 7591) ──
  if (path === "/register" && req.method === "POST") {
    const body = JSON.parse(await readBody(req));
    const clientId = randomBytes(16).toString("hex");
    const clientSecret = randomBytes(24).toString("hex");
    const client = {
      clientId,
      clientSecret,
      clientName: body.client_name || "Unnamed Client",
      redirectUris: body.redirect_uris || [],
      grantTypes: body.grant_types || ["authorization_code"],
    };
    clients.set(clientId, client);
    sendJson(res, 201, {
      client_id: clientId,
      client_secret: clientSecret,
      client_name: client.clientName,
      redirect_uris: client.redirectUris,
      grant_types: client.grantTypes,
    });
    return;
  }

  // ── Authorization Endpoint (with PKCE) ──
  if (path === "/authorize" && req.method === "GET") {
    const clientId = url.searchParams.get("client_id") || "";
    const redirectUri = url.searchParams.get("redirect_uri") || "";
    const state = url.searchParams.get("state") || "";
    const codeChallenge = url.searchParams.get("code_challenge") || undefined;
    const codeChallengeMethod = url.searchParams.get("code_challenge_method") || undefined;
    const responseType = url.searchParams.get("response_type") || "";

    if (responseType !== "code") {
      sendJson(res, 400, { error: "unsupported_response_type" });
      return;
    }

    // Authenticate user (cookie or existing session)
    const user = authenticateToken(req);
    if (!user) {
      // Redirect to Google login, then back to /authorize
      const loginUrl = new URL(`${BASE_URL}/auth/google`);
      loginUrl.searchParams.set("return_to", req.url || "/");
      sendRedirect(res, loginUrl.toString());
      return;
    }

    // Issue authorization code
    const code = randomBytes(24).toString("hex");
    authCodes.set(code, {
      clientId, email: user.email, redirectUri,
      codeChallenge, codeChallengeMethod,
      expires: Date.now() + 10 * 60 * 1000, // 10min
    });

    const redirect = new URL(redirectUri);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);
    sendRedirect(res, redirect.toString());
    return;
  }

  // ── Device Code Endpoint ──
  if (path === "/device/code" && req.method === "POST") {
    const body = new URLSearchParams(await readBody(req));
    const clientId = body.get("client_id") || "unknown";
    const dc = randomBytes(16).toString("hex");
    const uc = generateUserCode();
    deviceCodes.set(dc, {
      clientId, userCode: uc, email: null,
      status: "pending", expires: Date.now() + DEVICE_CODE_TTL * 1000,
    });
    sendJson(res, 200, {
      device_code: dc,
      user_code: uc,
      verification_uri: `${BASE_URL}/device`,
      verification_uri_complete: `${BASE_URL}/device?user_code=${uc}`,
      expires_in: DEVICE_CODE_TTL,
      interval: DEVICE_CODE_POLL_INTERVAL,
    });
    return;
  }

  // ── Device Authorization Page ──
  if (path === "/device" && req.method === "GET") {
    const userCode = url.searchParams.get("user_code") || "";
    const user = authenticateToken(req);

    if (!user) {
      const loginUrl = new URL(`${BASE_URL}/auth/google`);
      loginUrl.searchParams.set("return_to", req.url || "/device");
      sendRedirect(res, loginUrl.toString());
      return;
    }

    if (!userCode) {
      sendHtml(res, 200,
        `<h1>Device Authorization</h1>` +
        `<p>Enter the code displayed on your device:</p>` +
        `<form method="POST" action="/device/authorize">` +
        `<input name="user_code" placeholder="XXXX-XXXX" required /> ` +
        `<button type="submit">Authorize</button>` +
        `</form>` +
        `<p style="color:#666;margin-top:16px">Logged in as: <code>${user.email}</code></p>`
      );
      return;
    }

    // Auto-submit if user_code in URL
    sendHtml(res, 200,
      `<h1>Device Authorization</h1>` +
      `<p>Authorize device with code: <strong>${userCode}</strong></p>` +
      `<form method="POST" action="/device/authorize">` +
      `<input type="hidden" name="user_code" value="${userCode}" />` +
      `<button type="submit">Authorize</button>` +
      `</form>` +
      `<p style="color:#666">Logged in as: <code>${user.email}</code></p>`
    );
    return;
  }

  // ── Device Authorization Submit ──
  if (path === "/device/authorize" && req.method === "POST") {
    const user = authenticateToken(req);
    if (!user) { sendRedirect(res, "/device"); return; }

    const body = new URLSearchParams(await readBody(req));
    const userCode = body.get("user_code") || "";

    let found = false;
    for (const [dc, entry] of deviceCodes) {
      if (entry.userCode === userCode && entry.status === "pending" && entry.expires > Date.now()) {
        entry.email = user.email;
        entry.status = "authorized";
        found = true;
        break;
      }
    }

    if (found) {
      sendHtml(res, 200,
        `<h1>✅ Device Authorized</h1>` +
        `<p>Code <strong>${userCode}</strong> authorized for <code>${user.email}</code>.</p>` +
        `<p>You can close this tab.</p>`
      );
    } else {
      sendHtml(res, 400,
        `<h1>❌ Invalid or Expired Code</h1>` +
        `<p>The code <strong>${userCode}</strong> was not found or has expired.</p>`
      );
    }
    return;
  }

  // ── Token Endpoint ──
  if (path === "/token" && req.method === "POST") {
    const bodyStr = await readBody(req);
    let params: URLSearchParams;
    try {
      params = new URLSearchParams(bodyStr);
    } catch {
      const json = JSON.parse(bodyStr);
      params = new URLSearchParams(Object.entries(json).map(([k, v]) => [k, String(v)]));
    }

    const grantType = params.get("grant_type") || "";

    // ── Authorization Code ──
    if (grantType === "authorization_code") {
      const code = params.get("code") || "";
      const redirectUri = params.get("redirect_uri") || "";
      const codeVerifier = params.get("code_verifier") || "";
      const clientId = params.get("client_id") || "";

      const entry = authCodes.get(code);
      if (!entry || entry.expires < Date.now()) {
        if (entry) authCodes.delete(code);
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }

      // Verify redirect_uri matches
      if (entry.redirectUri && entry.redirectUri !== redirectUri) {
        authCodes.delete(code);
        sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
        return;
      }

      // Verify PKCE
      if (entry.codeChallenge) {
        if (!codeVerifier) {
          sendJson(res, 400, { error: "invalid_grant", error_description: "code_verifier required" });
          return;
        }
        const challenge = base64url(sha256(codeVerifier));
        if (challenge !== entry.codeChallenge) {
          authCodes.delete(code);
          sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
          return;
        }
      }

      authCodes.delete(code);
      const accessToken = signToken({ email: entry.email, sub: entry.email, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL });
      const rt = randomBytes(32).toString("hex");
      refreshTokens.set(rt, { clientId: entry.clientId || clientId, email: entry.email, expires: Date.now() + REFRESH_TOKEN_TTL * 1000 });

      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: rt,
        scope: "openid email profile",
      });
      return;
    }

    // ── Refresh Token ──
    if (grantType === "refresh_token") {
      const rt = params.get("refresh_token") || "";
      const entry = refreshTokens.get(rt);
      if (!entry || entry.expires < Date.now()) {
        if (entry) refreshTokens.delete(rt);
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }

      // Rotate refresh token
      refreshTokens.delete(rt);
      const newRt = randomBytes(32).toString("hex");
      refreshTokens.set(newRt, { ...entry, expires: Date.now() + REFRESH_TOKEN_TTL * 1000 });

      const accessToken = signToken({ email: entry.email, sub: entry.email, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL });
      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: newRt,
        scope: "openid email profile",
      });
      return;
    }

    // ── Device Code ──
    if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
      const dc = params.get("device_code") || "";
      const entry = deviceCodes.get(dc);

      if (!entry || entry.expires < Date.now()) {
        if (entry) deviceCodes.delete(dc);
        sendJson(res, 400, { error: "expired_token" });
        return;
      }

      if (entry.status === "pending") {
        sendJson(res, 400, { error: "authorization_pending" });
        return;
      }
      if (entry.status === "denied") {
        deviceCodes.delete(dc);
        sendJson(res, 400, { error: "access_denied" });
        return;
      }

      // Authorized
      deviceCodes.delete(dc);
      const accessToken = signToken({ email: entry.email, sub: entry.email, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL });
      const rt = randomBytes(32).toString("hex");
      refreshTokens.set(rt, { clientId: entry.clientId, email: entry.email!, expires: Date.now() + REFRESH_TOKEN_TTL * 1000 });

      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: rt,
        scope: "openid email profile",
      });
      return;
    }

    sendJson(res, 400, { error: "unsupported_grant_type" });
    return;
  }

  // ── Introspect ──
  if (path === "/introspect" && req.method === "POST") {
    const body = new URLSearchParams(await readBody(req));
    const token = body.get("token") || "";
    const payload = verifyToken(token) as { email?: string; exp?: number } | null;
    if (payload) {
      sendJson(res, 200, { active: true, email: payload.email, exp: payload.exp, token_type: "Bearer" });
    } else {
      sendJson(res, 200, { active: false });
    }
    return;
  }

  // ── Google OAuth (upstream) ──
  if (path === "/auth/google" && req.method === "GET") {
    const state = randomBytes(16).toString("hex");
    const returnTo = url.searchParams.get("return_to") || "/";
    const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    googleAuthUrl.searchParams.set("redirect_uri", `${BASE_URL}/auth/google/callback`);
    googleAuthUrl.searchParams.set("response_type", "code");
    googleAuthUrl.searchParams.set("scope", "openid email profile");
    googleAuthUrl.searchParams.set("state", `${state}:${Buffer.from(returnTo).toString("base64url")}`);
    googleAuthUrl.searchParams.set("access_type", "online");
    googleAuthUrl.searchParams.set("prompt", "consent");
    sendRedirect(res, googleAuthUrl.toString());
    return;
  }

  // ── Google OAuth Callback ──
  if (path === "/auth/google/callback" && req.method === "GET") {
    const code = url.searchParams.get("code");
    const stateParam = url.searchParams.get("state") || "";
    const [stateHash, returnToB64] = stateParam.split(":");
    const returnTo = returnToB64 ? Buffer.from(returnToB64, "base64url").toString() : "/";

    if (!code) { sendHtml(res, 400, "<h1>Missing code</h1>"); return; }

    try {
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: `${BASE_URL}/auth/google/callback`,
          grant_type: "authorization_code",
        }),
      });
      const tokenData = await tokenRes.json() as { id_token?: string; error?: string };
      if (!tokenData.id_token) {
        sendHtml(res, 401, `<h1>Token exchange failed</h1><pre>${JSON.stringify(tokenData)}</pre>`);
        return;
      }

      const payload = JSON.parse(Buffer.from(tokenData.id_token.split(".")[1], "base64").toString());
      const email: string = payload.email || "";
      const emailVerified = payload.email_verified;

      if (!emailVerified || !email.endsWith(`@${ALLOWED_DOMAIN}`)) {
        sendHtml(res, 403,
          `<h1>Access Denied</h1>` +
          `<p>Only <code>@${ALLOWED_DOMAIN}</code> accounts are allowed.</p>` +
          `<p>Your email: <code>${email || "unknown"}</code></p>`
        );
        return;
      }

      // Set session cookie (for backward compat / browser flows)
      const sid = randomBytes(24).toString("hex");
      sessions.set(sid, { email, expires: Date.now() + 24 * 60 * 60 * 1000 });

      res.writeHead(302, {
        Location: returnTo,
        "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
      });
      res.end();
    } catch (err: any) {
      sendHtml(res, 500, `<h1>OAuth error</h1><pre>${err.message}</pre>`);
    }
    return;
  }

  // ── Logout ──
  if (path === "/auth/logout" && req.method === "GET") {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies["sid"];
    if (sid) sessions.delete(sid);
    res.writeHead(302, {
      Location: "/",
      "Set-Cookie": "sid=; Path=/; HttpOnly; Max-Age=0",
    });
    res.end();
    return;
  }

  // ── Landing Page ──
  if (path === "/" && req.method === "GET") {
    if (AUTH_MODE === "oauth" && !authenticateToken(req)) {
      sendHtml(res, 200,
        `<h1>FreeWheel Docs MCP</h1>` +
        `<h3>Sign in</h3>` +
        `<ul>` +
        `<li><a href="/auth/google">Browser Login</a> (Google OAuth)</li>` +
        `<li><strong>Device Code</strong>: run your MCP client, it will show a code. Enter it at <a href="/device">/device</a></li>` +
        `</ul>` +
        `<hr/>` +
        `<p style="color:#666">MCP endpoint: <code>/mcp</code></p>` +
        `<p style="color:#666">Discovery: <a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a></p>`
      );
      return;
    }

    const user = authenticateToken(req);
    const email = user?.email || "anonymous";
    sendHtml(res, 200,
      `<h1>FreeWheel Docs MCP</h1>` +
      `<p>Logged in as: <code>${email}</code></p>` +
      `<p>MCP endpoint: <code>/mcp</code></p>` +
      `<p>Access token: use <code>/token</code> endpoint or <a href="/auth/google">re-authenticate</a></p>` +
      (AUTH_MODE === "oauth" ? `<p><a href="/auth/logout">Logout</a></p>` : "")
    );
    return;
  }

  // ── MCP Endpoint ──
  if (path === "/mcp") {
    if (AUTH_MODE === "oauth" && !authenticateToken(req)) {
      sendJson(res, 401, { error: "Unauthorized. Provide Bearer token or sign in at /auth/google." });
      return;
    }

    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const mcp = createMcpServer();
    await mcp.connect(transport);

    if (req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      await transport.handleRequest(req, res, body);
    } else {
      await transport.handleRequest(req, res);
    }
    return;
  }

  res.writeHead(404);
  res.end("Not Found");
});

httpServer.listen(PORT, HOST, () => {
  console.log(`MCP server listening on http://${HOST}:${PORT}`);
  console.log(`  /health → {ok:true}`);
  console.log(`  /mcp   → Streamable HTTP MCP`);
  console.log(`  /.well-known/oauth-authorization-server → Discovery`);
  if (AUTH_MODE === "oauth") {
    console.log(`  AUTH: OAuth 2.1 (PKCE + Device Code + RFC 7591)`);
    console.log(`  BASE_URL: ${BASE_URL}`);
  } else {
    console.log(`  AUTH: none (open)`);
  }
});
