"""Interoperability check: drives the example server with the Python MCP SDK, a client written
independently of the TypeScript SDK the server is built on.

    npm run example > harbor.log &          # the example prints its demo tokens to stdout
    pip install mcp==2.3.0
    python interop/python_client.py harbor.log

Covers token authentication and the whole OAuth flow (discovery, dynamic registration, the consent
page, PKCE, the issuer in the redirect, token exchange). Prints PASS or FAIL per check and exits
non-zero if any failed."""
import asyncio
import json
import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse

import httpx2
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata

URL = "http://localhost:8787/mcp"
LOG = sys.argv[1]
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def tokens():
    lines = open(LOG, encoding="utf-8").read().splitlines()
    found = {}
    for i, line in enumerate(lines):
        if line.startswith("    ") and i > 0:
            found[lines[i - 1].strip()] = line.strip()
    return found


def text_of(result):
    return "".join(getattr(block, "text", "") for block in result.content)


async def with_session(http_client, fn):
    async with streamable_http_client(URL, http_client=http_client) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            init = await session.initialize()
            return await fn(session, init)


async def pat_checks(tok):
    nell = next(v for k, v in tok.items() if k.startswith("Nell"))
    agent = next(v for k, v in tok.items() if "agent" in k)

    async with httpx2.AsyncClient() as bare:
        r = await bare.post(URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"accept": "application/json, text/event-stream"})
        check("no token -> 401 with a WWW-Authenticate challenge", r.status_code == 401 and "www-authenticate" in r.headers, f"{r.status_code} {r.headers.get('www-authenticate', '')[:70]}")
        r = await bare.post(URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"authorization": "Bearer hbr_pat_" + "A" * 43, "accept": "application/json, text/event-stream"})
        check("made-up token -> the same 401", r.status_code == 401, str(r.status_code))

    async def owner(session, init):
        check("initialize (Python SDK client)", bool(init.protocol_version), f"protocol {init.protocol_version}, server {init.server_info.name}")
        tools = (await session.list_tools()).tools
        names = sorted(t.name for t in tools)
        print("     tools offered to a read-only owner:", names)
        check("read-only owner is not offered write or proposal tools", "set_order_status" not in names and "propose_restock" not in names)
        schema = next(t for t in tools if t.name == "read_orders").input_schema
        print("     read_orders schema:", json.dumps(schema)[:200])

        own = await session.call_tool("read_orders", {"tenantId": "shop_fernhill", "limit": 10})
        body = text_of(own)
        check("owner reads own shop", not own.is_error, body[:80].replace("\n", " "))
        parsed = json.loads(body)
        check("result opens with the data notice", next(iter(parsed)) == "_notice", next(iter(parsed)))
        check("no line break or backtick survives in third-party text", "\\n" not in json.dumps(parsed.get("orders", parsed)) and "`" not in json.dumps(parsed.get("orders", parsed)))

        other = await session.call_tool("read_orders", {"tenantId": "shop_quayside", "limit": 10})
        check("owner cannot read another shop", bool(other.is_error), text_of(other)[:90])
        ghost = await session.call_tool("read_orders", {"tenantId": "shop_does_not_exist", "limit": 10})
        check("a shop that exists and one that does not get the same answer", text_of(other) == text_of(ghost), text_of(ghost)[:60])
        try:
            hidden = await session.call_tool("set_order_status", {"tenantId": "shop_fernhill", "orderId": "x", "status": "shipped"})
            check("calling a tool that was not offered fails", bool(hidden.is_error), text_of(hidden)[:80])
        except Exception as err:  # the SDK may raise on a protocol-level error
            check("calling a tool that was not offered fails", True, type(err).__name__)

    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {nell}"}) as c:
        await with_session(c, owner)

    async def agent_fn(session, init):
        names = sorted(t.name for t in (await session.list_tools()).tools)
        print("     tools offered to the agent:", names)
        check("agent may propose but is not offered the write tool", "propose_restock" in names and "set_order_status" not in names)

    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {agent}"}) as c:
        await with_session(c, agent_fn)


class Memory:
    def __init__(self):
        self.tokens = None
        self.client = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, info):
        self.client = info


async def oauth_checks():
    storage = Memory()
    captured = {}

    async def redirect_handler(authorization_url: str):
        # Stand in for the person at the consent page: load it, tick the read scopes, press Allow.
        async with httpx2.AsyncClient(follow_redirects=False) as browser:
            page = await browser.get(authorization_url)
            captured["consent_status"] = page.status_code
            captured["consent_names_client_host"] = "localhost" in page.text
            hidden = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', page.text))
            form = [(k, v.replace("&amp;", "&")) for k, v in hidden.items()]
            form += [("person", "user_nell"), ("scopes", "orders:read"), ("scopes", "stock:read"), ("decision", "allow")]
            back = await browser.post(authorization_url.split("?")[0], content=urlencode(form).encode(), headers={"content-type": "application/x-www-form-urlencoded"})
            captured["location"] = back.headers.get("location", "")
            captured["post_status"] = back.status_code

    async def callback_handler():
        query = parse_qs(urlparse(captured["location"]).query)
        fields = {"code": query["code"][0], "state": query.get("state", [None])[0]}
        if "iss" in AuthorizationCodeResult.model_fields and "iss" in query:
            fields["iss"] = query["iss"][0]
        captured["iss"] = query.get("iss", [None])[0]
        return AuthorizationCodeResult(**fields)

    provider = OAuthClientProvider(
        server_url=URL,
        client_metadata=OAuthClientMetadata(
            client_name="probe",
            redirect_uris=["http://localhost:3030/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    async def fn(session, init):
        names = sorted(t.name for t in (await session.list_tools()).tools)
        own = await session.call_tool("read_orders", {"tenantId": "shop_fernhill", "limit": 10})
        other = await session.call_tool("read_orders", {"tenantId": "shop_quayside", "limit": 10})
        return names, own, other

    async with httpx2.AsyncClient(auth=provider) as c:
        names, own, other = await with_session(c, fn)

    check("OAuth: discovery, dynamic registration and consent page", captured.get("consent_status") == 200 and captured.get("consent_names_client_host"), f"consent {captured.get('consent_status')}, approve {captured.get('post_status')}")
    check("OAuth: redirect back carries code, state and issuer", "code=" in captured.get("location", "") and captured.get("iss") is not None, f"iss={captured.get('iss')}")
    check("OAuth: token exchange with PKCE succeeded", storage.tokens is not None and bool(storage.tokens.access_token), f"type={getattr(storage.tokens, 'token_type', None)}, refresh={'yes' if getattr(storage.tokens, 'refresh_token', None) else 'no'}, scope={getattr(storage.tokens, 'scope', None)}")
    check("OAuth: the connection can read the shop it was granted", not own.is_error)
    check("OAuth: and only that shop", bool(other.is_error))
    check("OAuth: read-only consent offers no write tool", "set_order_status" not in names, str(names))


async def main():
    tok = tokens()
    await pat_checks(tok)
    try:
        await oauth_checks()
    except BaseException as err:  # report, do not hide
        import traceback

        traceback.print_exc()
        check("OAuth flow completed", False, repr(err)[:200])
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


asyncio.run(main())
