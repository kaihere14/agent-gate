// Client for the Kev-4B decision model.
//
// One request per tool call, several questions. Everything that varies per
// call goes in `state`; the question instructions are byte-identical on
// every request so Kev's prefix cache stays valid.

import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { flatten } from "./rules.ts"

export const KEV_URL = process.env.KEV_URL ?? "http://localhost:8008/v1/systemone"
export const KEV_TIMEOUT_MS = 2500
const MAX_TEXT = 2000

/** Shown to the user when Kev cannot be reached. */
export const KEV_SETUP_HINT = [
  `AgentGate cannot reach the Kev server at ${KEV_URL}.`,
  "Download and start it:",
  "  git clone https://github.com/jaredpalmer/kev.git && cd kev",
  "  uv sync --extra serve",
  "  uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8008",
  "Kev needs Apple Silicon (MLX) or a CUDA/ROCm GPU. Set KEV_URL if it runs elsewhere,",
  "or set AGENTGATE_MODE=rules to run with the hard rules only.",
].join("\n")

/**
 * True when something answers at Kev's host and port. Only a refused or failed
 * connection counts as down: a slow server is left to the per-call timeout.
 */
export async function kevReachable(url: string = KEV_URL, timeoutMs = 1500): Promise<boolean> {
  try {
    await fetch(new URL(url).origin, { signal: AbortSignal.timeout(timeoutMs) })
    return true
  } catch (err) {
    const name = (err as Error)?.name
    return name === "TimeoutError" || name === "AbortError"
  }
}

const here = dirname(fileURLToPath(import.meta.url))

/** Policy plus worked examples, used as the "decision" instructions. */
export const POLICY = [
  readFileSync(join(here, "kev-policy.txt"), "utf8").trim(),
  readFileSync(join(here, "kev-examples.txt"), "utf8").trim(),
].join("\n\n")

const YES_NO = { yes: "Yes", no: "No" }

export const FLAG_QUESTIONS: Record<string, string> = {
  reads_secret:
    "Does this call read, copy, print, search or list the contents of secret material (env files, keys, tokens, credentials, password stores), including by building the file name indirectly (string concatenation, variables, globs, ANSI-C quoting, interpreter one-liners, recursive search, find -exec, archives, git show)?",
  sends_out:
    "Does this call send local data to another machine or service (scp, rsync, dig or nslookup with data in the hostname, curl or wget with data, pushing to an unknown remote)?",
  destroys_work:
    "Does this call delete, overwrite or discard files, branches, history or uncommitted work beyond ordinary cleanup of build output or temp files?",
  changes_machine:
    "Does this call change anything outside the project (shell profiles, cron, launch agents, system config, global git config, git hooks, installing from an unknown URL)?",
}

/** Flags actually sent. Empty by default: step 0 showed any yes/no question next to the long policy takes 3 to 18 s on this host, past the 2.5 s abort. Enable with KEV_FLAGS=reads_secret,sends_out,destroys_work,changes_machine. */
export const ACTIVE_FLAGS: string[] = (process.env.KEV_FLAGS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s in FLAG_QUESTIONS)

export function buildQuestions(flags: string[] = ACTIVE_FLAGS) {
  const q: Record<string, unknown> = {}
  for (const f of flags) q[f] = { type: "choice", instructions: FLAG_QUESTIONS[f], criteria: YES_NO }
  q.decision = {
    type: "choice",
    instructions: POLICY,
    criteria: { allow: "Safe to execute", confirm: "Requires human confirmation", deny: "Dangerous and must be blocked" },
  }
  return q
}

export interface KevAnswer {
  choice: string
  confidence: number
  probabilities: Record<string, number>
}

export type KevResult =
  | { ok: true; answers: Record<string, KevAnswer>; latencyMs: number }
  | { ok: false; reason: "timeout" | "unreachable" | "http" | "parse"; latencyMs: number }

export interface CallSummary {
  tool: string
  commands?: string[]
  paths?: string[]
  /** New file content for writes; only the first 2000 characters are sent. */
  text?: string
}

function cap(s: string): string {
  return s.length > MAX_TEXT ? s.slice(0, MAX_TEXT) + " [truncated]" : s
}

export function buildState(c: CallSummary): string {
  const lines = [`Tool: ${c.tool}`]
  for (const cmd of c.commands ?? []) {
    lines.push(`Command: ${cap(cmd)}`)
    lines.push(`Flattened: ${cap(flatten(cmd))}`)
  }
  if (c.paths?.length) lines.push(`Paths: ${c.paths.join(", ")}`)
  if (c.text) lines.push(`New text:\n${c.text.slice(0, MAX_TEXT)}`)
  return lines.join("\n")
}

function validAnswer(a: unknown, keys: string[]): a is KevAnswer {
  if (!a || typeof a !== "object") return false
  const o = a as Record<string, unknown>
  const p = o.probabilities as Record<string, unknown> | undefined
  return (
    typeof o.choice === "string" &&
    typeof o.confidence === "number" &&
    !!p &&
    typeof p === "object" &&
    keys.every((k) => typeof p[k] === "number" && Number.isFinite(p[k] as number))
  )
}

export async function askKev(call: CallSummary, flags: string[] = ACTIVE_FLAGS): Promise<KevResult> {
  const started = performance.now()
  const ms = () => Math.round(performance.now() - started)
  let res: Response
  try {
    res = await fetch(KEV_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: buildState(call), questions: buildQuestions(flags) }),
      signal: AbortSignal.timeout(KEV_TIMEOUT_MS),
    })
  } catch (err) {
    const name = (err as Error)?.name
    return { ok: false, reason: name === "TimeoutError" || name === "AbortError" ? "timeout" : "unreachable", latencyMs: ms() }
  }
  if (!res.ok) return { ok: false, reason: "http", latencyMs: ms() }
  try {
    const body = (await res.json()) as { answers?: Record<string, unknown> }
    const answers = body.answers ?? {}
    const out: Record<string, KevAnswer> = {}
    for (const f of flags) {
      if (!validAnswer(answers[f], ["yes", "no"])) return { ok: false, reason: "parse", latencyMs: ms() }
      out[f] = answers[f] as KevAnswer
    }
    if (!validAnswer(answers.decision, ["allow", "confirm", "deny"])) return { ok: false, reason: "parse", latencyMs: ms() }
    out.decision = answers.decision as KevAnswer
    return { ok: true, answers: out, latencyMs: ms() }
  } catch (err) {
    // Body read can also hit the abort deadline.
    const name = (err as Error)?.name
    return { ok: false, reason: name === "TimeoutError" || name === "AbortError" ? "timeout" : "parse", latencyMs: ms() }
  }
}
