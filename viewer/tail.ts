// Live, colored view of the AgentGate decision log.
//
// Prints every record already in the log, then follows the file as new
// records are appended. Survives the file not existing yet, being truncated,
// or being replaced (log rotation).
//
// Usage:
//   bun viewer/tail.ts [log-path] [--no-follow] [--raw]
//   bun viewer/tail.ts flush [log-path]     empty the log (also: bun run tail flush)
//
// Log path resolution: CLI arg, then LOG_PATH from plugin/log.ts
// ($AGENT_GATE_LOG, else ~/.cline/data/agent-gate/decisions.jsonl).
//
// Two record shapes, both written by plugin/log.ts. Every field is optional;
// unknown fields are printed as extra key=value pairs so nothing is hidden.
//
// Message (logger.info / warn / error / debug):
//   ts, level, msg, ...fields
//
// Decision (logger.decision):
//   ts          ISO timestamp
//   decision    "ALLOW" | "CONFIRM" | "DENY"
//   layer       "rule" | "kev" | "policy" | "error"
//   tool        tool name, e.g. "run_commands", "read_files"
//   command     shell command (already redacted)
//   paths       string[] of file paths touched
//   rule        id of the hard rule that matched
//   category    rule category, e.g. "secrets", "exfil"
//   verdict     raw Kev verdict
//   confidence  Kev confidence, 0..1
//   reason      human-readable reason
//   latencyMs   time spent in the gate

import { closeSync, openSync, readFileSync, readSync, statSync, truncateSync, type Stats } from "node:fs"
import { LOG_PATH } from "../plugin/log.ts"

const argv = process.argv.slice(2)
const flush = argv[0] === "flush"
const args = flush ? argv.slice(1) : argv
const follow = !args.includes("--no-follow")
const raw = args.includes("--raw")
const logPath = args.find((a) => !a.startsWith("--")) ?? LOG_PATH

const POLL_MS = 200

const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s)
const c = {
  dim: paint("2"),
  bold: paint("1"),
  red: paint("31"),
  green: paint("32"),
  yellow: paint("33"),
  blue: paint("34"),
  magenta: paint("35"),
  cyan: paint("36"),
  gray: paint("90"),
  redBg: paint("1;97;41"),
  greenBg: paint("1;30;42"),
  yellowBg: paint("1;30;43"),
}

const KNOWN = new Set([
  "ts", "decision", "layer", "tool", "command", "paths", "rule", "category",
  "verdict", "confidence", "reason", "latencyMs",
])

const MESSAGE_KNOWN = new Set(["ts", "level", "msg"])

const counts: Record<string, number> = { ALLOW: 0, CONFIRM: 0, DENY: 0, messages: 0, other: 0 }

function badge(decision: unknown): string {
  const d = String(decision ?? "?").toUpperCase()
  const label = ` ${d.padEnd(7)} `
  if (d === "ALLOW") return c.greenBg(label)
  if (d === "CONFIRM") return c.yellowBg(label)
  if (d === "DENY") return c.redBg(label)
  return c.dim(label)
}

function layerTag(layer: unknown): string {
  const l = String(layer ?? "-")
  const tag = `[${l}]`.padEnd(8)
  if (l === "rule") return c.magenta(tag)
  if (l === "kev") return c.cyan(tag)
  if (l === "policy") return c.blue(tag)
  if (l === "error") return c.red(tag)
  return c.gray(tag)
}

function time(ts: unknown): string {
  if (typeof ts !== "string" && typeof ts !== "number") return c.gray("--:--:--.---")
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return c.gray(String(ts))
  return c.gray(d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"))
}

function fmtValue(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v)
}

function levelTag(level: unknown): string {
  const l = String(level ?? "info").toLowerCase()
  const tag = ` ${l.toUpperCase().padEnd(7)} `
  if (l === "error") return c.red(tag)
  if (l === "warn") return c.yellow(tag)
  if (l === "debug") return c.gray(tag)
  return c.blue(tag)
}

function extras(rec: Record<string, unknown>, known: Set<string>): string[] {
  return Object.entries(rec)
    .filter(([k]) => !known.has(k))
    .map(([k, v]) => `${k}=${fmtValue(v)}`)
}

function renderMessage(rec: Record<string, unknown>): string {
  counts.messages++
  const level = String(rec.level ?? "info").toLowerCase()
  const msg = fmtValue(rec.msg ?? "")
  const body = level === "error" ? c.red(msg) : level === "warn" ? c.yellow(msg) : level === "debug" ? c.gray(msg) : msg
  const rest = extras(rec, MESSAGE_KNOWN)
  return [time(rec.ts), levelTag(rec.level), body, rest.length ? c.dim(rest.join(" ")) : ""].filter(Boolean).join(" ")
}

function render(line: string): string {
  let rec: Record<string, unknown>
  try {
    const parsed = JSON.parse(line)
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error()
    rec = parsed
  } catch {
    counts.other++
    return c.dim(`  ${line}`)
  }

  if (raw) return line
  if (rec.decision === undefined && (rec.msg !== undefined || rec.level !== undefined)) return renderMessage(rec)

  const d = String(rec.decision ?? "").toUpperCase()
  counts[d === "ALLOW" || d === "CONFIRM" || d === "DENY" ? d : "other"]++

  const head = [time(rec.ts), badge(rec.decision), layerTag(rec.layer), c.bold(String(rec.tool ?? "?"))]
  if (typeof rec.latencyMs === "number") head.push(c.gray(`${rec.latencyMs}ms`))

  const lines = [head.join(" ")]
  const indent = "    "

  if (rec.command !== undefined) lines.push(indent + c.yellow("$ ") + fmtValue(rec.command))
  if (Array.isArray(rec.paths) && rec.paths.length) {
    lines.push(indent + c.gray("paths ") + rec.paths.map(String).join(", "))
  }

  const why: string[] = []
  if (rec.rule !== undefined) why.push(c.magenta(`rule=${fmtValue(rec.rule)}`))
  if (rec.category !== undefined) why.push(c.magenta(`category=${fmtValue(rec.category)}`))
  if (rec.verdict !== undefined) why.push(c.cyan(`kev=${fmtValue(rec.verdict)}`))
  if (typeof rec.confidence === "number") why.push(c.cyan(`conf=${rec.confidence.toFixed(2)}`))
  if (why.length) lines.push(indent + why.join(" "))

  if (rec.reason !== undefined) {
    const color = d === "DENY" ? c.red : d === "CONFIRM" ? c.yellow : c.green
    lines.push(indent + color("↳ " + fmtValue(rec.reason)))
  }

  const extra = extras(rec, KNOWN)
  if (extra.length) lines.push(indent + c.dim(extra.join(" ")))

  return lines.join("\n")
}

let offset = 0
let inode: number | undefined
let pending = ""
let waitingNoticeShown = false

function statOrNull(): Stats | null {
  try {
    return statSync(logPath)
  } catch {
    return null
  }
}

function readNew(): void {
  const st = statOrNull()
  if (!st) {
    if (!waitingNoticeShown) {
      console.log(c.gray(`waiting for ${logPath} ...`))
      waitingNoticeShown = true
    }
    return
  }
  waitingNoticeShown = false

  // Replaced (rotation) or truncated: start over from the top.
  if ((inode !== undefined && st.ino !== inode) || st.size < offset) {
    console.log(c.gray(`--- ${logPath} was rotated or truncated, reading from start ---`))
    offset = 0
    pending = ""
  }
  inode = st.ino
  if (st.size === offset) return

  const fd = openSync(logPath, "r")
  try {
    const buf = Buffer.alloc(st.size - offset)
    const n = readSync(fd, buf, 0, buf.length, offset)
    offset += n
    pending += buf.subarray(0, n).toString("utf8")
  } finally {
    closeSync(fd)
  }

  // Keep a trailing partial line until the writer finishes it.
  const parts = pending.split("\n")
  pending = parts.pop() ?? ""
  for (const line of parts) {
    if (line.trim()) console.log(render(line))
  }
}

function summary(): string {
  return [
    c.green(`ALLOW ${counts.ALLOW}`),
    c.yellow(`CONFIRM ${counts.CONFIRM}`),
    c.red(`DENY ${counts.DENY}`),
    c.blue(`messages ${counts.messages}`),
    c.gray(`other ${counts.other}`),
  ].join("  ")
}

/**
 * Empty the log in place. Truncating (not deleting) keeps the file the plugin
 * appends to, and a running tail notices and starts over from the top.
 */
function flushLog(): void {
  const st = statOrNull()
  if (!st) {
    console.log(c.gray(`nothing to flush, ${logPath} does not exist`))
    return
  }
  const records = readFileSync(logPath, "utf8").split("\n").filter((l) => l.trim()).length
  truncateSync(logPath, 0)
  console.log(c.green(`flushed ${records} record${records === 1 ? "" : "s"} (${st.size} bytes) from ${logPath}`))
}

if (flush) {
  flushLog()
  process.exit(0)
}

console.log(c.bold(`AgentGate log  ${c.gray(logPath)}`))
readNew()

if (!follow) {
  if (pending.trim()) console.log(render(pending))
  console.log(summary())
} else {
  const timer = setInterval(readNew, POLL_MS)
  process.on("SIGINT", () => {
    clearInterval(timer)
    console.log("\n" + summary())
    process.exit(0)
  })
}
