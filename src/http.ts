import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { randomBytes } from "node:crypto";

const PORT = parseInt(process.env.PORT || "3000");
const HOST = process.env.HOST || "0.0.0.0";
const DB_PATH = process.env.DB_PATH || "data/db/docs.sqlite";
const AUTH_MODE = process.env.AUTH_MODE || "none";
const BASE_URL = process.env.BASE_URL || "";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || "feedmob.com";

const db = new DatabaseSync(DB_PATH, { readOnly: true });

// In-memory session store: sessionId -> { email, expires }
const sessions = new Map<string, { email: string; expires: number }>();

function createMcpServer() {
  const server = new McpServer({ name: "freewheel-docs", version: "1.0.0" });

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

function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!header) return cookies;
  for (const part of header.split(";")) {
    const [key, ...vals] = part.trim().split("=");
    if (key) cookies[key.trim()] = vals.join("=").trim();
  }
  return cookies;
}

function isAuthenticated(req: IncomingMessage): boolean {
  if (AUTH_MODE !== "oauth") return true;
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies["sid"];
  if (!sid) return false;
  const session = sessions.get(sid);
  if (!session || session.expires < Date.now()) {
    if (sid) sessions.delete(sid);
    return false;
  }
  return true;
}

function sendJson(res: ServerResponse, status: number, body: object) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);

  // /health — always open
  if (url.pathname === "/health" && req.method === "GET") {
    sendJson(res, 200, { ok: true });
    return;
  }

  // /auth/google — redirect to Google consent screen
  if (url.pathname === "/auth/google" && req.method === "GET") {
    const state = randomBytes(16).toString("hex");
    const redirectUri = `${BASE_URL}/auth/google/callback`;
    const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    googleAuthUrl.searchParams.set("redirect_uri", redirectUri);
    googleAuthUrl.searchParams.set("response_type", "code");
    googleAuthUrl.searchParams.set("scope", "openid email profile");
    googleAuthUrl.searchParams.set("state", state);
    googleAuthUrl.searchParams.set("access_type", "online");
    googleAuthUrl.searchParams.set("prompt", "consent");
    res.writeHead(302, { Location: googleAuthUrl.toString() });
    res.end();
    return;
  }

  // /auth/google/callback — handle OAuth callback
  if (url.pathname === "/auth/google/callback" && req.method === "GET") {
    const code = url.searchParams.get("code");
    if (!code) {
      sendHtml(res, 400, "<h1>Missing code</h1>");
      return;
    }

    try {
      // Exchange code for tokens
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
      const tokenData = await tokenRes.json() as { id_token?: string; error?: string });
      if (!tokenData.id_token) {
        sendHtml(res, 401, `<h1>Token exchange failed</h1><pre>${JSON.stringify(tokenData)}</pre>`);
        return;
      }

      // Decode id_token (JWT) — just base64 decode the payload, no signature verify needed
      // since we just got it directly from Google's token endpoint
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

      // Create session
      const sid = randomBytes(24).toString("hex");
      sessions.set(sid, { email, expires: Date.now() + 24 * 60 * 60 * 1000 }); // 24h

      res.writeHead(302, {
        Location: "/",
        "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
      });
      res.end();
    } catch (err: any) {
      sendHtml(res, 500, `<h1>OAuth error</h1><pre>${err.message}</pre>`);
    }
    return;
  }

  // /auth/logout
  if (url.pathname === "/auth/logout" && req.method === "GET") {
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

  // / — simple landing page (shows login status)
  if (url.pathname === "/" && req.method === "GET") {
    if (AUTH_MODE === "oauth" && !isAuthenticated(req)) {
      sendHtml(res, 200,
        `<h1>FreeWheel Docs MCP</h1>` +
        `<p><a href="/auth/google">Sign in with Google (@${ALLOWED_DOMAIN})</a></p>`
      );
      return;
    }
    const cookies = parseCookies(req.headers.cookie);
    const session = cookies["sid"] ? sessions.get(cookies["sid"]) : null;
    const email = session?.email || "anonymous";
    sendHtml(res, 200,
      `<h1>FreeWheel Docs MCP</h1>` +
      `<p>Logged in as: <code>${email}</code></p>` +
      `<p>MCP endpoint: <code>/mcp</code></p>` +
      (AUTH_MODE === "oauth" ? `<p><a href="/auth/logout">Logout</a></p>` : "")
    );
    return;
  }

  // /mcp — MCP endpoint (auth required if oauth mode)
  if (url.pathname === "/mcp") {
    if (AUTH_MODE === "oauth" && !isAuthenticated(req)) {
      sendJson(res, 401, { error: "Unauthorized. Sign in at /auth/google first." });
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
  if (AUTH_MODE === "oauth") {
    console.log(`  AUTH: Google OAuth (@${ALLOWED_DOMAIN})`);
    console.log(`  BASE_URL: ${BASE_URL}`);
  } else {
    console.log(`  AUTH: none (open)`);
  }
});
