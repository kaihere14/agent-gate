// The two checks: hard rules first, then Kev for what the rules did not match.

import { askKev, KEV_SETUP_HINT, type KevResult } from "../kev.ts"
import type { Targets } from "../normalize.ts"
import { decide, type Action } from "../policy.ts"
import { checkCommand, checkPath, type RuleHit } from "../rules.ts"
import { CONFIRM_AS_DENY } from "./config.ts"
import { summarize } from "./input.ts"

export function ruleHits(t: Targets): RuleHit[] {
  const hits: RuleHit[] = []
  for (const c of t.commands) hits.push(...checkCommand(c))
  for (const p of t.reads) hits.push(...checkPath(p, "read"))
  for (const p of t.writes) hits.push(...checkPath(p, "write"))
  return hits
}

export interface RuleVerdict {
  /** Every matched rule id, comma separated, for the log. */
  rule: string
  first: RuleHit
}

/** The rule verdict for a call, or undefined when no rule matches. */
export function checkRules(t: Targets): RuleVerdict | undefined {
  const hits = ruleHits(t)
  if (hits.length === 0) return undefined
  return { rule: [...new Set(hits.map((h) => h.rule))].join(","), first: hits[0] }
}

export interface KevVerdict {
  action: Action
  /** Why, for the log. */
  why: string
  /** Why, for the agent: adds setup steps when Kev cannot be reached. */
  reason: string
  kev: KevResult
}

export async function checkKev(toolName: string, input: unknown, t: Targets): Promise<KevVerdict> {
  const kev = await askKev(summarize(toolName, input, t))
  const decided = decide(kev)
  const escalate = CONFIRM_AS_DENY && decided.action === "confirm"
  const action: Action = escalate ? "deny" : decided.action
  const why = escalate ? `confirm escalated to deny (AGENTGATE_CONFIRM=deny): ${decided.why}` : decided.why
  const reason = !kev.ok && kev.reason === "unreachable" ? `Kev: ${why}\n${KEV_SETUP_HINT}` : `Kev: ${why}`
  return { action, why, reason, kev }
}
