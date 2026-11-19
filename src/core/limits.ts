// Rate limits: by request and by cost.

export interface LimitRule {
  /** Units allowed per window. */
  limit: number;
  windowMs: number;
}

export interface LimitCharge {
  /** Namespaced key, for example `token:<id>`. */
  key: string;
  rule: LimitRule;
  /** Units this call consumes. A heavy read costs more than a light one. */
  cost?: number;
}

export interface LimitDecision {
  allowed: boolean;
  /** Seconds until the caller may try again. 0 when allowed. */
  retryAfterSeconds: number;
}

export interface RateLimiter {
  /**
   * Charges every key or none. A call refused by the second limit must not have been debited from
   * the first, or a caller near one ceiling burns the other one while being told to wait.
   */
  consume(charges: readonly LimitCharge[]): Promise<LimitDecision>;
}

/** The limits a guard applies. Every one can be overridden. */
export interface GuardLimits {
  /** Requests per IP before authentication. Bounds what a flood of forged tokens can cost. */
  anonymousPerIp: LimitRule;
  /** Requests per credential. */
  perCredential: LimitRule;
  /** Cost units per credential. */
  costPerCredential: LimitRule;
  /** Cost units per accountable user, across all of their credentials. */
  costPerUser: LimitRule;
  /** Token endpoint calls per IP. */
  tokenEndpointPerIp: LimitRule;
  /** Client registrations per IP. */
  registrationPerIp: LimitRule;
}

const MINUTE = 60_000;

export const DEFAULT_LIMITS: GuardLimits = {
  anonymousPerIp: { limit: 240, windowMs: MINUTE },
  perCredential: { limit: 120, windowMs: MINUTE },
  costPerCredential: { limit: 300, windowMs: MINUTE },
  costPerUser: { limit: 1000, windowMs: MINUTE },
  tokenEndpointPerIp: { limit: 30, windowMs: MINUTE },
  registrationPerIp: { limit: 5, windowMs: MINUTE },
};

/**
 * Sliding-window limiter held in memory. Correct for one process. Behind several instances each
 * one counts alone, so the effective limit is multiplied: use a shared store there.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, { at: number; cost: number }[]>();

  constructor(private readonly now: () => number = Date.now) {}

  async consume(charges: readonly LimitCharge[]): Promise<LimitDecision> {
    const now = this.now();
    let retryAfterMs = 0;

    for (const { key, rule, cost = 1 } of charges) {
      const recent = (this.hits.get(key) ?? []).filter((hit) => hit.at > now - rule.windowMs);
      this.hits.set(key, recent);
      const used = recent.reduce((sum, hit) => sum + hit.cost, 0);
      if (used + cost > rule.limit) {
        const oldest = recent[0]?.at ?? now;
        retryAfterMs = Math.max(retryAfterMs, oldest + rule.windowMs - now, 1000);
      }
    }
    if (retryAfterMs > 0) return { allowed: false, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };

    for (const { key, cost = 1 } of charges) this.hits.get(key)!.push({ at: now, cost });
    return { allowed: true, retryAfterSeconds: 0 };
  }
}
