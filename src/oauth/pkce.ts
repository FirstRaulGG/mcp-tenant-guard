// PKCE, S256 only.

import { createHash, timingSafeEqual } from "node:crypto";

// RFC 7636: 43 to 128 characters from the unreserved set.
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
// An S256 challenge is always 43 base64url characters.
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

export function isValidChallenge(challenge: unknown): challenge is string {
  return typeof challenge === "string" && CHALLENGE.test(challenge);
}

export function challengeFor(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function verifyPkce(verifier: unknown, challenge: string): boolean {
  if (typeof verifier !== "string" || !VERIFIER.test(verifier)) return false;
  const computed = Buffer.from(challengeFor(verifier));
  const stored = Buffer.from(challenge);
  return computed.length === stored.length && timingSafeEqual(computed, stored);
}
