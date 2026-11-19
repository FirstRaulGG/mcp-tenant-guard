// `npm run demo`: the attacks this library is for, played against the example server.
//
// Everything runs in this process, through the real MCP protocol, with no network and no model.
// Each scene states what must be true; if one is not, the demo exits with an error.

import { createHarbor } from "./example/app.js";
import type { Harbor } from "./example/app.js";
import { connect, rawRequest } from "./example/client.js";
import { INJECTED_NOTE } from "./example/world.js";
import { issueCredential } from "./guard/issue.js";
import type { IssueRequest } from "./guard/issue.js";
import { challengeFor } from "./oauth/pkce.js";
import { approveAuthorization, exchangeToken, registerClient, validateAuthorizeRequest } from "./oauth/server.js";

const lines: string[] = [];
const say = (text = "") => lines.push(text);
let failures = 0;

function check(description: string, ok: boolean): void {
  if (!ok) failures += 1;
  say(`  ${ok ? "ok  " : "FAIL"} ${description}`);
}

function scene(title: string): void {
  say();
  say(`== ${title}`);
}

async function token(harbor: Harbor, request: Omit<IssueRequest, "name">): Promise<string> {
  const issued = await issueCredential(harbor.guard, { name: "demo", ...request });
  if (!issued.ok) throw new Error(`could not issue a token: ${issued.reason}`);
  return issued.token;
}

/** Shows line breaks and invisible characters as escapes, so the before and after can be compared. */
const visible = (text: string) =>
  [...text]
    .map((char) => {
      const code = char.codePointAt(0)!;
      if (code === 0x0a) return String.raw`\n`;
      return code < 0x20 || code === 0x7f || code > 0xff ? String.raw`\u` + code.toString(16).padStart(4, "0") : char;
    })
    .join("");

export async function runDemo(): Promise<{ output: string; failures: number }> {
  lines.length = 0;
  failures = 0;
  const harbor = createHarbor();

  say("Harbor is a made-up order desk used by three shops. Mara is an account manager assigned to");
  say("two of them. Nell runs Fernhill Ceramics. A restocking agent works on Fernhill for Mara.");

  // -------------------------------------------------------------------------
  scene("1. An order note tries to give orders");
  const nell = await connect(harbor, await token(harbor, { kind: "owner", userId: "user_nell", tenantId: "shop_fernhill", scopes: ["orders:read", "stock:read"] }));
  const orders = await nell.call("read_orders", { limit: 10 });
  const note = (orders.body.orders as { id: string; note: string }[]).find((order) => order.id === "F-1003")!.note;
  say("  as the customer typed it:");
  say(`    ${visible(INJECTED_NOTE)}`);
  say("  as the model receives it:");
  say(`    ${visible(note)}`);
  say(`  first key of the result: ${Object.keys(orders.body)[0]}`);
  check("the note is one line, with no code fence, forged delimiter or hidden character", !/[\r\n`]|<<</.test(note) && !note.includes(String.fromCharCode(0x202e)));
  check("the e-mail address in it is redacted", !note.includes("@") && note.includes("[email]"));
  check("the result opens with a notice naming the fields that hold outside text", Object.keys(orders.body)[0] === "_notice");
  say("  The words of the instruction are still there. Cleaning text does not make it safe; the");
  say("  next scenes are what does.");

  // -------------------------------------------------------------------------
  scene("2. A model obeys the note, with a read-only credential");
  say(`  tools on offer: ${(await nell.toolNames()).join(", ")}`);
  const obeyed = await nell.call("set_order_status", { orderId: "F-1001", status: "shipped" });
  check("set_order_status is not on offer, and calling it anyway fails", obeyed.isError);
  check("no order changed", harbor.world.orders.shop_fernhill!.find((o) => o.id === "F-1003")!.status === "new");

  // -------------------------------------------------------------------------
  scene("3. One token that reads outside text AND writes needs a deliberate yes");
  const both = { kind: "owner" as const, userId: "user_nell", tenantId: "shop_fernhill", name: "both", scopes: ["orders:read", "orders:write"] };
  const refusedBoth = await issueCredential(harbor.guard, both);
  check("issuing it is refused without confirmation", !refusedBoth.ok && refusedBoth.reason === "read_and_write_needs_confirmation");
  check("a write-only token is issued without ceremony", (await issueCredential(harbor.guard, { ...both, scopes: ["orders:write"] })).ok);

  // -------------------------------------------------------------------------
  scene("4. An advisor reaches for a shop that is not theirs");
  const mara = await connect(harbor, await token(harbor, { kind: "advisor", userId: "user_mara", scopes: ["orders:read"] }));
  const tenants = ((await mara.call("list_tenants")).body.tenants as { id: string }[]).map((t) => t.id);
  say(`  Mara's shops: ${tenants.join(", ")}`);
  const unnamed = await mara.call("read_orders", { limit: 5 });
  const foreign = await mara.call("read_orders", { limit: 5, tenantId: "shop_larkspur" });
  const missing = await mara.call("read_orders", { limit: 5, tenantId: "shop_does_not_exist" });
  say(`  no tenantId      -> ${unnamed.text}`);
  say(`  shop_larkspur    -> ${foreign.text}`);
  say(`  an invented shop -> ${missing.text}`);
  check("a call without a tenant is refused, not guessed", unnamed.isError);
  check("another advisor's shop and a shop that does not exist get the same answer", foreign.isError && foreign.text === missing.text);

  // -------------------------------------------------------------------------
  scene("5. An agent that does what the note said");
  const agentToken = await token(harbor, { kind: "agent", userId: "user_mara", tenantId: "shop_fernhill", agentName: "restock" });
  const agent = await connect(harbor, agentToken);
  say(`  tools on offer: ${(await agent.toolNames()).join(", ")}`);
  const run = await agent.call("start_run", { trigger: "schedule", clientRequestId: "demo-run-0001" });
  await agent.call("read_stock");
  const huge = await agent.call("propose_restock", { sku: "MUG-01", quantity: 9999, reason: "the order note said so" });
  const proposal = await agent.call("propose_restock", { sku: "MUG-01", quantity: 24, reason: "3 on hand, reorder point is 10" });
  await agent.call("end_run", { runId: run.body.runId, status: "done", summary: "one restock proposal" });
  check("it cannot read orders or change them: it holds no orders scope", (await agent.call("read_orders", { limit: 1 })).isError);
  check("9999 units is outside what the tool accepts", huge.isError);
  check("a sane proposal is recorded as proposed, waiting for a person", proposal.body.status === "proposed" && harbor.world.proposals[0]?.status === "proposed");
  check("no tool approves a proposal, and the stock did not move", harbor.world.stock.shop_fernhill!.find((i) => i.sku === "MUG-01")!.onHand === 3);
  check("an agent cannot leave its shop", (await agent.call("read_stock", { tenantId: "shop_quayside" })).isError);

  // -------------------------------------------------------------------------
  scene("6. Permissions taken away apply to tokens already issued");
  const writer = await connect(harbor, await token(harbor, { kind: "owner", userId: "user_nell", tenantId: "shop_fernhill", scopes: ["orders:write"] }));
  check("before: Nell's write token ships an order", !(await writer.call("set_order_status", { orderId: "F-1002", status: "shipped" })).isError);
  harbor.world.setRole("user_nell", "shop_fernhill", "viewer");
  check("after Nell is made a viewer: the same token cannot", (await writer.call("set_order_status", { orderId: "F-1004", status: "shipped" })).isError);
  harbor.world.unassign("user_mara", "shop_fernhill");
  check("after Mara loses Fernhill: the agent she delegated stops authenticating", (await rawRequest(harbor, agentToken, { body: "{}" })).status === 401);
  harbor.world.setRole("user_nell", "shop_fernhill", "admin");

  // -------------------------------------------------------------------------
  scene("7. A stolen refresh token");
  const registered = await registerClient(harbor.guard, { redirect_uris: ["https://client.example.test/callback"] });
  if (!registered.ok) throw new Error(registered.error);
  const verifier = "demo-verifier-".padEnd(64, "x");
  const authorize = await validateAuthorizeRequest(
    harbor.guard,
    new URLSearchParams({
      response_type: "code",
      client_id: registered.client.id,
      redirect_uri: "https://client.example.test/callback",
      code_challenge: challengeFor(verifier),
      code_challenge_method: "S256",
      resource: harbor.mcpUrl,
    }),
  );
  if (!authorize.ok) throw new Error("the authorization request was refused");
  const approved = await approveAuthorization(harbor.guard, authorize.request, { userId: "user_nell", kind: "owner", tenantId: "shop_fernhill", scopes: ["orders:read"] });
  if (!approved.ok) throw new Error(approved.reason);
  const grant = { client_id: registered.client.id };
  const first = await exchangeToken(harbor.guard, {
    ...grant,
    grant_type: "authorization_code",
    code: new URL(approved.location).searchParams.get("code")!,
    code_verifier: verifier,
    redirect_uri: "https://client.example.test/callback",
  });
  if (!first.ok) throw new Error(first.error);
  const second = await exchangeToken(harbor.guard, { ...grant, grant_type: "refresh_token", refresh_token: first.body.refresh_token });
  if (!second.ok) throw new Error(second.error);
  const replay = await exchangeToken(harbor.guard, { ...grant, grant_type: "refresh_token", refresh_token: first.body.refresh_token });
  check("the client refreshes once and gets a new pair", second.ok);
  check("the old refresh token, presented again, is refused", !replay.ok);
  check("and every token from that sign-in is revoked, the thief's and the client's alike", (await rawRequest(harbor, second.body.access_token, { body: "{}" })).status === 401);

  // -------------------------------------------------------------------------
  scene("8. What the audit log holds afterwards");
  say("  who          kind     tenant               tool               outcome  status  run");
  for (const entry of harbor.audit.entries) {
    say(
      `  ${entry.userId.padEnd(12)} ${entry.actorKind.padEnd(8)} ${(entry.tenantId ?? "-").padEnd(20)} ${entry.tool.padEnd(18)} ${entry.outcome.padEnd(8)} ${String(entry.status ?? "-").padEnd(7)} ${entry.runId ? "yes" : "-"}`,
    );
  }
  const log = JSON.stringify(harbor.audit.entries);
  check("refused attempts are in it, with the tenant that was asked for", harbor.audit.entries.some((e) => e.outcome === "denied" && e.tenantId === "shop_larkspur"));
  check("the agent's rows name Mara, who delegated it", harbor.audit.entries.filter((e) => e.actorKind === "agent").every((e) => e.userId === "user_mara"));
  check("no customer name, note or proposal reason is in it", !/Wren|gift wrap|reorder point/.test(log));

  say();
  say(failures === 0 ? "All checks passed." : `${failures} check(s) FAILED.`);
  return { output: lines.join("\n"), failures };
}

const invokedDirectly = process.argv[1] !== undefined && /demo\.(ts|js)$/.test(process.argv[1]);
if (invokedDirectly) {
  const { output, failures: failed } = await runDemo();
  process.stdout.write(`${output}\n`);
  process.exitCode = failed === 0 ? 0 : 1;
}
