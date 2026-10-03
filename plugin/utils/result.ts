// What the beforeTool hook hands back to Cline for each outcome.

import type { Action } from "../policy.ts"
import type { RuleVerdict } from "./checks.ts"

/** allow: run it. confirm: Cline's approval prompt. deny: skip it and tell the agent why. */
export function toResult(action: Action, reason: string) {
  if (action === "allow") return undefined
  if (action === "confirm") return { policy: { autoApprove: false } }
  return { skip: true, reason: `AgentGate denied this call: ${reason}` }
}

/** A rule deny names the rule so the agent can see which pattern it hit. */
export function ruleDenyResult(v: RuleVerdict) {
  return { skip: true, reason: `${v.first.rule}: ${v.first.reason}` }
}
