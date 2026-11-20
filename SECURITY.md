# Security

This library sits between AI agents and business data, so reports of holes are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue for something exploitable. Use GitHub's private reporting instead: the **Report a vulnerability** button under this repository's **Security** tab. It opens a private thread with the maintainer.

Include what you can of:

- the version or commit;
- what an attacker needs (a token of which kind, which scopes, which tenant);
- what they get that they should not;
- the smallest request, tool call or test that shows it.

You can expect an acknowledgement within a week. This is a one-person project with no bounty.

## What counts

In scope: anything that lets a credential act outside its tenant or scopes, bypass the tool pipeline or the audit log, obtain or forge a token, or abuse the OAuth endpoints (redirects, code or refresh-token handling).

Already known and documented in the README under **Limits**, so not news: prompt injection that stays within a credential's own scopes, an advisor's credential spanning its own tenants, handlers that ignore the tenant they were given, and the in-memory stores not being fit for production.

## Supported versions

Only the latest commit on `main`.
