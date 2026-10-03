// Reading a raw tool call: its name, its input, and the summary sent to Kev.

import type { CallSummary } from "../kev.ts"
import type { Targets } from "../normalize.ts"

export function toolNameOf(tool: { name?: string } | undefined, toolCall: unknown): string {
  return tool?.name ?? (toolCall as { name?: string } | undefined)?.name ?? "unknown"
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

export function countTargets(t: Targets): number {
  return t.commands.length + t.reads.length + t.writes.length
}

export function summarize(toolName: string, input: unknown, t: Targets): CallSummary {
  const o = (input && typeof input === "object" ? input : {}) as Record<string, unknown>
  const text = typeof o.new_text === "string" ? o.new_text : typeof o.content === "string" ? o.content : undefined
  return { tool: toolName, commands: t.commands, paths: [...t.reads, ...t.writes], text }
}
