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
 *
 * Keys whose window has passed are dropped as it goes, so memory follows the number of callers
 * active in the last window, not the number ever seen.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, { windowMs: number; entries: { at: number; cost: number }[] }>();
  private calls = 0;

  constructor(
    private readonly now: () => number = Date.now,
    /** How many `consume` calls between sweeps of idle keys. */
    private readonly sweepEvery = 500,
  ) {}

  /** Number of keys currently held. For tests and monitoring. */
  get size(): number {
    return this.hits.size;
  }

  private sweep(now: number): void {
    for (const [key, bucket] of this.hits) {
      const last = bucket.entries[bucket.entries.length - 1];
      if (!last || last.at <= now - bucket.windowMs) this.hits.delete(key);
    }
  }

  async consume(charges: readonly LimitCharge[]): Promise<LimitDecision> {
    const now = this.now();
    if ((this.calls += 1) % this.sweepEvery === 0) this.sweep(now);
    let retryAfterMs = 0;

    for (const { key, rule, cost = 1 } of charges) {
      // A cost that is not a positive number would compare false against every limit.
      if (!Number.isFinite(cost) || cost <= 0) throw new Error("a rate-limit cost must be a positive number");
      const recent = (this.hits.get(key)?.entries ?? []).filter((hit) => hit.at > now - rule.windowMs);
      const used = recent.reduce((sum, hit) => sum + hit.cost, 0);
      if (used + cost > rule.limit) {
        const oldest = recent[0]?.at ?? now;
        retryAfterMs = Math.max(retryAfterMs, oldest + rule.windowMs - now, 1000);
      }
      if (recent.length > 0) this.hits.set(key, { windowMs: rule.windowMs, entries: recent });
      else this.hits.delete(key);
    }
    if (retryAfterMs > 0) return { allowed: false, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };

    for (const { key, rule, cost = 1 } of charges) {
      const bucket = this.hits.get(key) ?? { windowMs: rule.windowMs, entries: [] };
      bucket.entries.push({ at: now, cost });
      this.hits.set(key, bucket);
    }
    return { allowed: true, retryAfterSeconds: 0 };
  }
}
