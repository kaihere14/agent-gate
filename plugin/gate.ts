// AgentGate: a Cline plugin that checks every tool call before it runs.
// Order: extract targets, hard rules, then Kev. Helpers live in ./utils.

import type { AgentPlugin } from "@cline/sdk"
import { KEV_SETUP_HINT, kevReachable } from "./kev.ts"
import { extractTargets, INSPECTED_TOOLS } from "./normalize.ts"
import { checkKev, checkRules } from "./utils/checks.ts"
import { MODE } from "./utils/config.ts"
import { countTargets, parseInput, toolNameOf } from "./utils/input.ts"
import { record, recordStop } from "./utils/record.ts"
import { ruleDenyResult, toResult } from "./utils/result.ts"

let cwd = process.cwd()

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
      recordStop("kev unreachable at run start")
      return { stop: true, reason: KEV_SETUP_HINT }
    },
    async beforeTool({ tool, toolCall, input }) {
      const started = performance.now()
      const toolName = toolNameOf(tool, toolCall)
      try {
        const parsed = parseInput(toolName, input)
        const targets = extractTargets(toolName, parsed, cwd)
        const found = countTargets(targets)

        // A tool we know touches the shell or files, but nothing could be extracted: fail closed.
        if (INSPECTED_TOOLS.has(toolName) && found === 0) {
          const why = `could not read the ${toolName} input, so it cannot be checked`
          record({ tool: toolName, layer: "error", action: "deny", started, input: parsed, why })
          return toResult("deny", why)
        }

        if (MODE !== "kev") {
          const hit = checkRules(targets)
          if (hit) {
            record({ tool: toolName, layer: "rule", action: "deny", started, input: parsed, rule: hit.rule, why: hit.first.reason })
            return ruleDenyResult(hit)
          }
        }

        // Nothing for Kev to judge (no command or path), or rules-only ablation.
        if (MODE === "rules" || found === 0) {
          record({ tool: toolName, layer: "rule", action: "allow", started, input: parsed })
          return undefined
        }

        const v = await checkKev(toolName, parsed, targets)
        record({ tool: toolName, layer: "kev", action: v.action, started, input: parsed, kev: v.kev, why: v.why })
        return toResult(v.action, v.reason)
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
