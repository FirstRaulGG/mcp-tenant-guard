// Which redirect URIs a client may register.
//
// The authorization code is delivered to the redirect URI, so this list decides who can receive
// one. It is an allowlist, and every rule is applied to the PARSED URL: a string prefix check
// accepts `https://good.example.evil.test` and `https://good.example@evil.test`.

export interface RedirectFamily {
  /** Exact hostname. No wildcards. */
  host: string;
  /** Path before the variable part, starting and ending with `/`. */
  pathPrefix: string;
  /** Longest accepted variable segment. */
  maxSegmentLength: number;
  /** If set, the variable segment must end with this text. */
  segmentSuffix?: string;
}

export interface RedirectPolicy {
  /** Complete URIs accepted as written. */
  exact?: readonly string[];
  /**
   * For clients whose callback carries one random path segment per connection, so the full URI
   * cannot be listed: `https://<host><pathPrefix><segment>`.
   */
  families?: readonly RedirectFamily[];
  /**
   * Accept `http://127.0.0.1:<port>/...` and `http://localhost:<port>/...`, for native and
   * command-line clients that listen on a local port.
   */
  allowLoopback?: boolean;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
export const MAX_REDIRECT_URI_LENGTH = 2000;

export function isAllowedRedirect(policy: RedirectPolicy, uri: unknown): uri is string {
  if (typeof uri !== "string" || uri.length === 0 || uri.length > MAX_REDIRECT_URI_LENGTH) return false;
  if (policy.exact?.includes(uri)) return true;

  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  // Never acceptable outside the exact list: credentials in the URL, or a fragment.
  if (url.username || url.password || url.hash) return false;
  // The parser normalises `/a/../b`. Refusing any URI that does not survive a round trip keeps
  // what was checked identical to what will be redirected to.
  if (url.href !== uri) return false;

  if (policy.allowLoopback && url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost")) {
    return !url.search;
  }

  if (url.protocol !== "https:" || url.port || url.search) return false;
  for (const family of policy.families ?? []) {
    if (url.hostname !== family.host || !url.pathname.startsWith(family.pathPrefix)) continue;
    const segment = url.pathname.slice(family.pathPrefix.length);
    if (!segment || segment.length > family.maxSegmentLength || !SEGMENT.test(segment)) continue;
    if (family.segmentSuffix && !segment.endsWith(family.segmentSuffix)) continue;
    return true;
  }
  return false;
}

/** The host shown to a person on the consent screen. Taken from the URI, never from what the client calls itself. */
export function redirectHost(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return "unknown";
  }
}
