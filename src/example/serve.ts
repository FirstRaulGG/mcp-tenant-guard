// `npm run example`: the example server on http://localhost:8787, for trying a real MCP client.
//
// THIS IS A DEMO. The consent page lets you pick who you are from a list, because the example has
// no login. In a real application that page sits behind your own session, and the person is
// whoever is signed in. Everything is kept in memory and gone when the process exits.

import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

import { issueCredential } from "../guard/issue.js";
import { approveAuthorization, denyAuthorization, validateAuthorizeRequest } from "../oauth/server.js";
import { createHarbor } from "./app.js";
import { TENANTS } from "./world.js";

const PORT = Number(process.env.PORT ?? 8787);
const ORIGIN = `http://localhost:${PORT}`;
const harbor = createHarbor({ origin: ORIGIN });

/** Who you can pretend to be on the consent page. */
const PEOPLE = [
  { id: "user_nell", label: "Nell, admin of Fernhill Ceramics", kind: "owner", tenantId: "shop_fernhill" },
  { id: "user_jun", label: "Jun, viewer at Fernhill Ceramics", kind: "owner", tenantId: "shop_fernhill" },
  { id: "user_mara", label: "Mara, account manager (Fernhill and Quayside)", kind: "advisor", tenantId: null },
] as const;

const escapeHtml = (text: string) =>
  text.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);

function page(title: string, body: string): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem}fieldset{margin:1rem 0;border:1px solid #bbb;border-radius:6px}label{display:block;margin:.25rem 0}button{font:inherit;padding:.5rem 1rem;margin-right:.5rem}.warn{background:#fff3cd;padding:.5rem .75rem;border-radius:6px}</style>
</head><body>${body}</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:*", "x-frame-options": "DENY" },
  });
}

async function authorizePage(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const params = request.method === "POST" ? new URLSearchParams(await request.text()) : url.searchParams;
  const check = await validateAuthorizeRequest(harbor.guard, params);
  if (!check.ok) {
    return check.kind === "redirect" ? Response.redirect(check.location, 302) : page("Cannot continue", `<h1>Cannot continue</h1><p>${escapeHtml(check.message)}</p>`);
  }

  if (request.method === "POST") {
    if (params.get("decision") !== "allow") return Response.redirect(denyAuthorization(harbor.guard, check.request), 302);
    const person = PEOPLE.find((p) => p.id === params.get("person"));
    if (!person) return page("Cannot continue", "<h1>Cannot continue</h1><p>Choose who you are.</p>");
    const result = await approveAuthorization(harbor.guard, check.request, {
      userId: person.id,
      kind: person.kind,
      tenantId: person.tenantId,
      scopes: params.getAll("scopes"),
      confirmReadAndWrite: params.get("confirm") === "yes",
    });
    if (result.ok) return Response.redirect(result.location, 302);
    return page("Cannot continue", `<h1>Not granted</h1><p>${escapeHtml(result.message)}</p><p>Use the back button to change your choice.</p>`);
  }

  const hidden = [...url.searchParams].map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`).join("");
  const people = PEOPLE.map((p, i) => `<label><input type="radio" name="person" value="${p.id}"${i === 0 ? " checked" : ""}> ${escapeHtml(p.label)}</label>`).join("");
  const scopes = harbor.guard.scopes.all
    .map((scope) => `<label><input type="checkbox" name="scopes" value="${scope}"${harbor.guard.scopes.natureOf(scope) === "read" ? " checked" : ""}> ${scope} <small>(${harbor.guard.scopes.natureOf(scope)})</small></label>`)
    .join("");
  return page(
    "Connect to Harbor",
    `<h1>Connect to Harbor</h1>
<p class="warn">Demo only: there is no login here, so you choose who you are.</p>
<p>An application at <strong>${escapeHtml(check.request.clientHost)}</strong> is asking to connect.</p>
<form method="post">${hidden}
<fieldset><legend>You are</legend>${people}</fieldset>
<fieldset><legend>It may</legend>${scopes}
<label><input type="checkbox" name="confirm" value="yes"> I understand that reading and writing with one connection lets text in an order note trigger a change</label></fieldset>
<button name="decision" value="allow">Allow</button><button name="decision" value="deny">Decline</button>
</form>`,
  );
}

async function toRequest(req: IncomingMessage): Promise<Request> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(key, value);
  }
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  return new Request(`${ORIGIN}${req.url ?? "/"}`, { method: req.method, headers, body: hasBody ? Buffer.concat(chunks) : undefined });
}

async function send(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.end(Buffer.from(await response.arrayBuffer()));
}

const server = createServer((req, res) => {
  void (async () => {
    try {
      const request = await toRequest(req);
      const { pathname } = new URL(request.url);
      const response = pathname === "/oauth/authorize" && (request.method === "GET" || request.method === "POST")
        ? await authorizePage(request)
        : await harbor.fetch(request);
      await send(res, response);
    } catch {
      res.statusCode = 400;
      res.end();
    }
  })();
});

async function demoToken(label: string, request: Parameters<typeof issueCredential>[1]): Promise<void> {
  const issued = await issueCredential(harbor.guard, request);
  if (issued.ok) process.stdout.write(`  ${label}\n    ${issued.token}\n`);
}

server.listen(PORT, "127.0.0.1", () => {
  void (async () => {
    process.stdout.write(`Harbor example on ${ORIGIN}  (MCP endpoint: ${harbor.mcpUrl})\n`);
    process.stdout.write(`Shops: ${TENANTS.map((t) => `${t.id} (${t.name})`).join(", ")}\n\n`);
    process.stdout.write("Tokens for this run. They live in memory and die with this process:\n");
    await demoToken("Nell, read-only on her shop", { kind: "owner", userId: "user_nell", tenantId: "shop_fernhill", name: "example", scopes: ["orders:read", "stock:read"] });
    await demoToken("Mara, advisor, read-only", { kind: "advisor", userId: "user_mara", name: "example", scopes: ["orders:read", "stock:read"] });
    await demoToken("restock agent on Fernhill", { kind: "agent", userId: "user_mara", tenantId: "shop_fernhill", agentName: "restock", name: "example" });
    process.stdout.write("\nA client that speaks OAuth can also connect to the endpoint with no token and sign in.\n");
  })();
});
