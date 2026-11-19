// Opaque bearer tokens: how they look, how they are stored, when they stop working.
//
// A token is `<brand>_<class>_<43 base64url chars>`: 32 random bytes, 256 bits. Nothing is encoded
// in it. What a token may do is looked up on every request, so shrinking a permission takes effect
// on tokens that were already issued.

import { createHash, createHmac, randomBytes } from "node:crypto";

export const TOKEN_BODY_LENGTH = 43;

/** What a token is for. The class is part of the visible prefix, so a leak is easy to triage. */
export type TokenClass = "pat" | "agent" | "access" | "refresh";

const CLASS_TAG: Record<TokenClass, string> = { pat: "pat", agent: "agt", access: "atk", refresh: "rtk" };

const BRAND = /^[a-z][a-z0-9]{1,15}$/;
const BODY = /^[A-Za-z0-9_-]+$/;

export function assertBrand(brand: string): void {
  if (!BRAND.test(brand)) throw new Error("token brand must be 2-16 lowercase letters or digits, starting with a letter");
}

export function tokenPrefix(brand: string, tokenClass: TokenClass): string {
  return `${brand}_${CLASS_TAG[tokenClass]}_`;
}

export function randomSecret(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export interface IssuedToken {
  /** Shown to the person once and never stored. */
  token: string;
  /** Prefix plus the first 8 characters: enough to recognise a token in a list, useless to replay. */
  label: string;
}

export function generateToken(brand: string, tokenClass: TokenClass): IssuedToken {
  const prefix = tokenPrefix(brand, tokenClass);
  const body = randomSecret();
  return { token: prefix + body, label: `${prefix}${body.slice(0, 8)}` };
}

/**
 * The class of a well-formed token, or null. Runs before any storage lookup: text that cannot be
 * one of our tokens never costs a query.
 */
export function classifyToken(brand: string, raw: string): TokenClass | null {
  for (const tokenClass of Object.keys(CLASS_TAG) as TokenClass[]) {
    const prefix = tokenPrefix(brand, tokenClass);
    if (!raw.startsWith(prefix)) continue;
    const body = raw.slice(prefix.length);
    return body.length === TOKEN_BODY_LENGTH && BODY.test(body) ? tokenClass : null;
  }
  return null;
}

/** 1 = SHA-256 of the token. 2 = HMAC-SHA-256 keyed with a server-side pepper. */
export type HashVersion = 1 | 2;

export interface TokenHash {
  hash: string;
  version: HashVersion;
}

/**
 * Only the hash is stored. There is no per-token salt on purpose: the token is 256 random bits, so
 * there is no dictionary to defend against, and a salt would rule out a lookup by unique index.
 * The pepper covers the other case, a copy of the table without the application's secrets.
 */
export function hashToken(token: string, pepper?: string | null): TokenHash {
  if (pepper) return { hash: createHmac("sha256", pepper).update(token).digest("hex"), version: 2 };
  return { hash: createHash("sha256").update(token).digest("hex"), version: 1 };
}

/** Hashes to look a token up by, strongest first. Rows written before a pepper existed stay findable. */
export function candidateHashes(token: string, pepper?: string | null): TokenHash[] {
  return pepper ? [hashToken(token, pepper), hashToken(token, null)] : [hashToken(token, null)];
}

export type TokenUsability = "ok" | "revoked" | "expired";

export function tokenUsability(row: { revokedAt: Date | null; expiresAt: Date | null }, now: Date): TokenUsability {
  if (row.revokedAt) return "revoked";
  // `<=`: at the expiry instant the token is already dead.
  if (row.expiresAt && row.expiresAt.getTime() <= now.getTime()) return "expired";
  return "ok";
}

export const DEFAULT_TTL_DAYS = 90;
export const MAX_TTL_DAYS = 365;
const DAY_MS = 86_400_000;

/**
 * Expiry for a new personal token. A lifetime outside 1..365 days is refused, not clamped: someone
 * who asked for "never" should hear that it is not on offer.
 */
export function expiryFor(ttlDays: number | undefined, now: Date): Date | null {
  const days = ttlDays ?? DEFAULT_TTL_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > MAX_TTL_DAYS) return null;
  return new Date(now.getTime() + days * DAY_MS);
}

/** `lastUsedAt` is written at most this often per token. */
export const LAST_USED_THROTTLE_MS = 5 * 60_000;

export function shouldTouchLastUsed(lastUsedAt: Date | null, now: Date): boolean {
  return !lastUsedAt || now.getTime() - lastUsedAt.getTime() >= LAST_USED_THROTTLE_MS;
}
