// One log record per gate decision: commands and paths kept, file bodies dropped.

import type { KevResult } from "../kev.ts"
import { log } from "../log.ts"
import type { Action } from "../policy.ts"
import { MODE } from "./config.ts"

export function elapsed(started: number): number {
  return Math.round(performance.now() - started)
}

/** Kev probabilities for every question, for the log. */
export function kevProbs(kev: KevResult): Record<string, Record<string, number>> | undefined {
  if (!kev.ok) return undefined
  return Object.fromEntries(Object.entries(kev.answers).map(([k, a]) => [k, a.probabilities]))
}

const REDACT_KEY = /content|text|patch|diff|^input$/i

/** Params for the log: commands and paths kept, file bodies and patches dropped. */
export function redactParams(value: unknown, depth = 0): unknown {
  if (depth > 6 || value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map((v) => redactParams(v, depth + 1))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value)) {
    out[k] = REDACT_KEY.test(k) && typeof v === "string" ? `[redacted ${v.length} chars]` : redactParams(v, depth + 1)
  }
  return out
}

export function record(fields: {
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

/** The run was stopped before any tool call. */
export function recordStop(why: string) {
  log({ layer: "error", action: "stop", mode: MODE, why })
}
