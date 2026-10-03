// Turns Kev's answers into one action. Pure: no I/O, no clock.
//
// Kev can only make a call stricter than "allowed by the rules", so every
// signal votes and the strictest vote wins. Thresholds live in CONFIG so
// tests/sweep.ts can tune them without code changes.

import type { KevResult } from "./kev.ts"

export type Action = "allow" | "confirm" | "deny"

export const CONFIG = {
  /** allow only if p(allow) is at least this */
  T_ALLOW: 0.65,
  /** deny if p(deny) is at least this */
  T_DENY: 0.5,
  /** yes/no flags: p(yes) at or above this is a strong signal */
  T_FLAG_DENY: 0.6,
  /** yes/no flags: p(yes) at or above this asks the human */
  T_FLAG_CONFIRM: 0.2,
}

export type Config = typeof CONFIG

/** Flags whose strong "yes" denies outright. The rest only confirm. */
const DENY_FLAGS = new Set(["reads_secret", "sends_out"])

const RANK: Record<Action, number> = { allow: 0, confirm: 1, deny: 2 }

export function decide(kev: KevResult, cfg: Config = CONFIG): { action: Action; why: string } {
  if (!kev.ok) {
    return kev.reason === "timeout"
      ? { action: "confirm", why: "kev timed out" }
      : { action: "deny", why: `kev failed: ${kev.reason}` }
  }

  const votes: { action: Action; why: string }[] = []
  let flagged = false

  for (const [name, a] of Object.entries(kev.answers)) {
    if (name === "decision") continue
    const p = a.probabilities.yes ?? 0
    if (p >= cfg.T_FLAG_DENY) {
      flagged = true
      votes.push({ action: DENY_FLAGS.has(name) ? "deny" : "confirm", why: `${name} p(yes)=${p.toFixed(2)}` })
    } else if (p >= cfg.T_FLAG_CONFIRM) {
      flagged = true
      votes.push({ action: "confirm", why: `${name} p(yes)=${p.toFixed(2)}` })
    }
  }

  const d = kev.answers.decision.probabilities
  const pAllow = d.allow ?? 0
  const pDeny = d.deny ?? 0
  if (pDeny >= cfg.T_DENY) votes.push({ action: "deny", why: `decision p(deny)=${pDeny.toFixed(2)}` })
  else if (pAllow >= cfg.T_ALLOW && !flagged) votes.push({ action: "allow", why: `decision p(allow)=${pAllow.toFixed(2)}` })
  else votes.push({ action: "confirm", why: `decision p(allow)=${pAllow.toFixed(2)} p(deny)=${pDeny.toFixed(2)}` })

  let best = votes[0]
  for (const v of votes) if (RANK[v.action] > RANK[best.action]) best = v
  const why = votes.filter((v) => v.action === best.action).map((v) => v.why).join("; ")
  return { action: best.action, why }
}
