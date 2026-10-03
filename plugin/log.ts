// Append-only JSONL logger for AgentGate.
//
// Every record is one JSON object per line, written synchronously so nothing
// is lost if the host kills the hook at its time limit. Secrets are redacted
// from every string before it touches disk. Logging never throws: a broken
// log must not break the gate.
//
// Log path: $AGENT_GATE_LOG, else ~/.cline/data/agent-gate/decisions.jsonl.
// Watch it live with `bun viewer/tail.ts`.

import { appendFileSync, mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"

export const LOG_PATH =
  process.env.AGENT_GATE_LOG ?? join(homedir(), ".cline", "data", "agent-gate", "decisions.jsonl")

export type Decision = "ALLOW" | "CONFIRM" | "DENY"
export type Layer = "rule" | "kev" | "policy" | "error"
export type Level = "debug" | "info" | "warn" | "error"

export interface DecisionRecord {
  decision: Decision
  layer: Layer
  tool: string
  command?: string
  paths?: string[]
  rule?: string
  category?: string
  verdict?: string
  confidence?: number
  reason?: string
  latencyMs?: number
  [extra: string]: unknown
}

const MAX_STRING = 2000

// Order matters: whole private key blocks first, then specific token shapes,
// then generic key=value assignments.
const SECRET_PATTERNS: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED:private-key]"],
  [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED:aws-key]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED:github-token]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "[REDACTED:github-token]"],
  [/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED:api-key]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED:slack-token]"],
  [/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED:jwt]"],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [REDACTED]"],
  [/(\/\/[^\s:/@]+:)[^\s@/]+@/g, "$1[REDACTED]@"],
  [
    /\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Za-z0-9_]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"']+)/gi,
    "$1$2[REDACTED]",
  ],
]

export function redact(text: string): string {
  let out = text
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement)
  if (out.length > MAX_STRING) out = out.slice(0, MAX_STRING) + `…[+${out.length - MAX_STRING} chars]`
  return out
}

function scrub(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return redact(value)
  if (value instanceof Error) return { name: value.name, message: redact(value.message) }
  if (depth > 6 || value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value)) out[k] = scrub(v, depth + 1)
  return out
}

let dirReady = false

/** Append one raw record. Adds `ts`, redacts secrets, never throws. */
export function log(record: Record<string, unknown>): void {
  try {
    if (!dirReady) {
      mkdirSync(dirname(LOG_PATH), { recursive: true })
      dirReady = true
    }
    const line = JSON.stringify({ ts: new Date().toISOString(), ...(scrub(record) as object) })
    appendFileSync(LOG_PATH, line + "\n")
  } catch {
    // Swallow: logging must never take the gate down.
  }
}

function at(level: Level) {
  return (msg: string, fields?: Record<string, unknown>) => log({ level, msg, ...fields })
}

/** Drop-in replacement for console.log inside the plugin. */
export const logger = {
  debug: at("debug"),
  info: at("info"),
  warn: at("warn"),
  error: at("error"),
  /** Record a gate decision for a tool call. */
  decision: (record: DecisionRecord) => log(record),
}

export default logger
