// Turns a raw tool call into what the rules check: shell commands, paths
// read, and paths written.
//
// Cline's built-in tools accept several input shapes (a string, an array, an
// object, objects with `command` + `args`, `path` / `file_path` / `filePath`
// ...), so extraction walks the input instead of trusting one schema.
// Unknown tools are scanned for command- and path-like keys, and their paths
// are treated as writes, the stricter choice.

import { homedir } from "node:os"
import { isAbsolute, resolve } from "node:path"

export interface Targets {
  commands: string[]
  reads: string[]
  writes: string[]
}

const PATH_KEYS = new Set(["path", "file_path", "filePath", "file", "filename", "files", "paths", "directory", "dir", "cwd"])
const COMMAND_KEYS = new Set(["command", "commands", "cmd", "script"])
const MAX_DEPTH = 6

export function resolvePath(p: string, cwd: string): string {
  const home = homedir()
  const expanded = p.replace(/^(?:~|\$\{?HOME\}?)(?=\/|$)/, home)
  return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded)
}

/** Shell-quote args so `{command: "rm", args: ["-rf", "/"]}` checks as `rm -rf /`. */
function joinCommand(command: string, args: unknown): string {
  if (!Array.isArray(args) || args.length === 0) return command
  const quoted = args.map((a) => {
    const s = String(a)
    return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`
  })
  return [command, ...quoted].join(" ")
}

function collectCommands(value: unknown, out: string[], depth = 0): void {
  if (depth > MAX_DEPTH || value == null) return
  if (typeof value === "string") {
    if (value.trim()) out.push(value)
  } else if (Array.isArray(value)) {
    for (const v of value) collectCommands(v, out, depth + 1)
  } else if (typeof value === "object") {
    const o = value as Record<string, unknown>
    if (typeof o.command === "string") out.push(joinCommand(o.command, o.args))
    for (const [k, v] of Object.entries(o)) {
      if (k !== "command" && k !== "args" && COMMAND_KEYS.has(k)) collectCommands(v, out, depth + 1)
    }
  }
}

function collectPaths(value: unknown, out: string[], depth = 0): void {
  if (depth > MAX_DEPTH || value == null) return
  if (typeof value === "string") {
    if (value.trim()) out.push(value)
  } else if (Array.isArray(value)) {
    for (const v of value) collectPaths(v, out, depth + 1)
  } else if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (PATH_KEYS.has(k)) collectPaths(v, out, depth + 1)
    }
  }
}

/** apply_patch headers: `*** Add File: x`, `*** Update File: x`, `*** Delete File: x`, `*** Move to: x`. */
function patchPaths(patch: string): string[] {
  const out: string[] = []
  for (const m of patch.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$/gm)) out.push(m[1])
  return out
}

/** Any command-like or path-like keys anywhere in an unknown tool's input. */
function scanUnknown(value: unknown, t: Targets, depth = 0): void {
  if (depth > MAX_DEPTH || value == null || typeof value !== "object") return
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (COMMAND_KEYS.has(k)) collectCommands(k === "command" ? value : v, t.commands)
    else if (PATH_KEYS.has(k)) collectPaths(v, t.writes)
    else scanUnknown(v, t, depth + 1)
  }
}

/** Tools whose input must yield at least one command or path, or the call is denied. */
export const INSPECTED_TOOLS = new Set(["run_commands", "read_files", "editor", "apply_patch"])

export function extractTargets(toolName: string, input: unknown, cwd: string): Targets {
  const t: Targets = { commands: [], reads: [], writes: [] }
  const raw: string[] = []

  switch (toolName) {
    case "run_commands":
      collectCommands(input, t.commands)
      break
    case "read_files":
      collectPaths(input, raw)
      t.reads.push(...raw)
      break
    case "editor":
      collectPaths(input, raw)
      t.writes.push(...raw)
      break
    case "apply_patch": {
      const patch = typeof input === "string" ? input : (input as { input?: unknown } | null)?.input
      if (typeof patch === "string") t.writes.push(...patchPaths(patch))
      break
    }
    default:
      scanUnknown(input, t)
  }

  t.commands = [...new Set(t.commands)]
  t.reads = [...new Set(t.reads.map((p) => resolvePath(p, cwd)))]
  t.writes = [...new Set(t.writes.map((p) => resolvePath(p, cwd)))]
  return t
}
