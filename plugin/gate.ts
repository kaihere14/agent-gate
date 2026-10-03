import type { AgentPlugin } from "@cline/sdk"
import { askKev, KEV_SETUP_HINT, kevReachable, type CallSummary, type KevResult } from "./kev.ts"
import { log } from "./log.ts"
import { extractTargets, INSPECTED_TOOLS, type Targets } from "./normalize.ts"
import { decide, type Action } from "./policy.ts"
import { checkCommand, checkPath, type RuleHit } from "./rules.ts"

/** both (default) | rules | kev. "kev" skips the rule check, for ablation runs. */
export type Mode = "both" | "rules" | "kev"
const MODE: Mode = (["both", "rules", "kev"] as const).find((m) => m === process.env.AGENTGATE_MODE) ?? "both"
/** AGENTGATE_CONFIRM=deny turns Kev's confirm into a block, for unattended runs where nobody answers the prompt. */
const CONFIRM_AS_DENY = process.env.AGENTGATE_CONFIRM === "deny"

let cwd = process.cwd()

function elapsed(started: number): number {
  return Math.round(performance.now() - started)
}

/** run_commands sometimes arrives with `commands` as a JSON-encoded string. */
export function parseInput(toolName: string, input: unknown): unknown {
  if (toolName !== "run_commands") return input
  const decode = (v: unknown) => {
    if (typeof v !== "string" || !/^\s*[[{"]/.test(v)) return v
    try {
      return JSON.parse(v)
    } catch {
      return v
    }
  }
  const top = decode(input)
  if (top && typeof top === "object" && !Array.isArray(top) && "commands" in top) {
    return { ...(top as object), commands: decode((top as { commands: unknown }).commands) }
  }
  return top
}

export function ruleHits(t: Targets): RuleHit[] {
  const hits: RuleHit[] = []
  for (const c of t.commands) hits.push(...checkCommand(c))
  for (const p of t.reads) hits.push(...checkPath(p, "read"))
  for (const p of t.writes) hits.push(...checkPath(p, "write"))
  return hits
}

export function summarize(toolName: string, input: unknown, t: Targets): CallSummary {
  const o = (input && typeof input === "object" ? input : {}) as Record<string, unknown>
  const text = typeof o.new_text === "string" ? o.new_text : typeof o.content === "string" ? o.content : undefined
  return { tool: toolName, commands: t.commands, paths: [...t.reads, ...t.writes], text }
}

/** Kev probabilities for every question, for the log. */
export function kevProbs(kev: KevResult): Record<string, Record<string, number>> | undefined {
  if (!kev.ok) return undefined
  return Object.fromEntries(Object.entries(kev.answers).map(([k, a]) => [k, a.probabilities]))
}

const REDACT_KEY = /content|text|patch|diff|^input$/i

/** Params for the log: commands and paths kept, file bodies and patches dropped. */
function redactParams(value: unknown, depth = 0): unknown {
  if (depth > 6 || value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map((v) => redactParams(v, depth + 1))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value)) {
    out[k] = REDACT_KEY.test(k) && typeof v === "string" ? `[redacted ${v.length} chars]` : redactParams(v, depth + 1)
  }
  return out
}

function record(fields: {
  tool: string
  layer: "rule" | "kev" | "error"
  action: Action
  started: number
  input: unknown
  rule?: string
  kev?: KevResult
  why?: string
}) {
  log({
    tool: fields.tool,
    layer: fields.layer,
    action: fields.action,
    mode: MODE,
    rule: fields.rule,
    kev: fields.kev ? (fields.kev.ok ? kevProbs(fields.kev) : { error: fields.kev.reason }) : undefined,
    kev_latency_ms: fields.kev?.latencyMs,
    why: fields.why,
    latency_ms: elapsed(fields.started),
    // A bare string input (apply_patch) is the patch body itself.
    params: typeof fields.input === "string" ? `[redacted ${fields.input.length} chars]` : redactParams(fields.input),
  })
}

function toResult(action: Action, reason: string) {
  if (action === "allow") return undefined
  if (action === "confirm") return { policy: { autoApprove: false } }
  return { skip: true, reason: `AgentGate denied this call: ${reason}` }
}

const plugin: AgentPlugin = {
  name: "agent-gate",
  manifest: { capabilities: ["hooks"] },
  setup(_api, ctx) {
    if (ctx.workspaceInfo?.rootPath) cwd = ctx.workspaceInfo.rootPath
  },
  hooks: {
    // Stop the run up front with setup steps, instead of denying every call that reaches Kev.
    async beforeRun() {
      if (MODE === "rules" || (await kevReachable())) return undefined
      log({ layer: "error", action: "stop", mode: MODE, why: "kev unreachable at run start" })
      return { stop: true, reason: KEV_SETUP_HINT }
    },
    async beforeTool({ tool, toolCall, input }) {
      const started = performance.now()
      const toolName = tool?.name ?? (toolCall as { name?: string } | undefined)?.name ?? "unknown"
      try {
        const parsed = parseInput(toolName, input)
        const targets = extractTargets(toolName, parsed, cwd)
        const found = targets.commands.length + targets.reads.length + targets.writes.length

        // A tool we know touches the shell or files, but nothing could be extracted: fail closed.
        if (INSPECTED_TOOLS.has(toolName) && found === 0) {
          const why = `could not read the ${toolName} input, so it cannot be checked`
          record({ tool: toolName, layer: "error", action: "deny", started, input: parsed, why })
          return toResult("deny", why)
        }

        if (MODE !== "kev") {
          const hits = ruleHits(targets)
          if (hits.length > 0) {
            const first = hits[0]
            const rule = [...new Set(hits.map((h) => h.rule))].join(",")
            record({ tool: toolName, layer: "rule", action: "deny", started, input: parsed, rule, why: first.reason })
            return { skip: true, reason: `${first.rule}: ${first.reason}` }
          }
        }

        // Nothing for Kev to judge (no command or path), or rules-only ablation.
        if (MODE === "rules" || found === 0) {
          record({ tool: toolName, layer: "rule", action: "allow", started, input: parsed })
          return undefined
        }

        const kev = await askKev(summarize(toolName, parsed, targets))
        const decided = decide(kev)
        const escalate = CONFIRM_AS_DENY && decided.action === "confirm"
        const action: Action = escalate ? "deny" : decided.action
        const why = escalate ? `confirm escalated to deny (AGENTGATE_CONFIRM=deny): ${decided.why}` : decided.why
        record({ tool: toolName, layer: "kev", action, started, input: parsed, kev, why })
        const reason = !kev.ok && kev.reason === "unreachable" ? `Kev: ${why}\n${KEV_SETUP_HINT}` : `Kev: ${why}`
        return toResult(action, reason)
      } catch (err) {
        // Cline ignores hook errors and runs the tool anyway, so a crash here must deny.
        const why = `internal error while checking this call: ${(err as Error)?.message ?? err}`
        record({ tool: toolName, layer: "error", action: "deny", started, input, why })
        return toResult("deny", "internal error while checking this call")
      }
    },
  },
}

export default plugin
