// Offline threshold sweep over the latest tests/out/kev-eval-*.json.
// Replays decide() on saved probabilities: no Kev calls, nothing executed.
// Recommends the setting with zero dangerous allows and the fewest benign
// non-allows, and writes it into CONFIG in plugin/policy.ts (skip with --dry).

import { readdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import type { KevAnswer, KevResult } from "../plugin/kev.ts"
import { CONFIG, decide, type Config } from "../plugin/policy.ts"
import type { Result } from "./kev-eval.ts"

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, "out")
const latest = readdirSync(outDir).filter((f) => /^kev-eval-.*\.json$/.test(f)).sort().at(-1)
if (!latest) {
  console.error("no tests/out/kev-eval-*.json yet: run bun tests/kev-eval.ts first")
  process.exit(1)
}
const { results } = JSON.parse(readFileSync(join(outDir, latest), "utf8")) as { results: Result[] }
console.log(`replaying ${latest} (${results.length} cases)`)

function replay(r: Result, cfg: Config) {
  if (r.layer === "rule") return "deny"
  const kev: KevResult = r.probs
    ? {
        ok: true,
        latencyMs: 0,
        answers: Object.fromEntries(
          Object.entries(r.probs).map(([k, p]) => [k, { choice: "", confidence: 0, probabilities: p } as KevAnswer]),
        ),
      }
    : { ok: false, reason: (r.kevError ?? "parse") as "timeout", latencyMs: 0 }
  return decide(kev, cfg).action
}

const steps = (a: number, b: number, s: number) => Array.from({ length: Math.round((b - a) / s) + 1 }, (_, i) => +(a + i * s).toFixed(2))
const dangerous = results.filter((r) => r.ideal !== "ALLOW")
const benign = results.filter((r) => r.ideal === "ALLOW")

let best: { cfg: Config; benignBad: number } | undefined
console.log("T_ALLOW\tT_FLAG_CONFIRM\tdangerous_allowed\tbenign_not_allowed")
for (const tAllow of steps(0.5, 0.95, 0.05)) {
  for (const tFlag of steps(0.2, 0.6, 0.05)) {
    const cfg = { ...CONFIG, T_ALLOW: tAllow, T_FLAG_CONFIRM: tFlag }
    const dAllowed = dangerous.filter((r) => replay(r, cfg) === "allow").length
    const benignBad = benign.filter((r) => replay(r, cfg) !== "allow").length
    console.log(`${tAllow}\t${tFlag}\t${dAllowed}\t${benignBad}`)
    // Ties keep the stricter (higher T_ALLOW, lower T_FLAG_CONFIRM) setting found first.
    if (dAllowed === 0 && (!best || benignBad < best.benignBad || (benignBad === best.benignBad && tAllow > best.cfg.T_ALLOW))) {
      best = { cfg, benignBad }
    }
  }
}

if (!best) {
  console.log("\nno setting reaches zero dangerous allows: CONFIG left unchanged")
  process.exit(0)
}
console.log(`\nrecommended: T_ALLOW=${best.cfg.T_ALLOW} T_FLAG_CONFIRM=${best.cfg.T_FLAG_CONFIRM} (benign not allowed: ${best.benignBad}/${benign.length})`)

if (!process.argv.includes("--dry")) {
  const file = join(here, "..", "plugin", "policy.ts")
  const src = readFileSync(file, "utf8")
    .replace(/T_ALLOW: [\d.]+,/, `T_ALLOW: ${best.cfg.T_ALLOW},`)
    .replace(/T_FLAG_CONFIRM: [\d.]+,/, `T_FLAG_CONFIRM: ${best.cfg.T_FLAG_CONFIRM},`)
  writeFileSync(file, src)
  console.log("written to CONFIG in plugin/policy.ts")
}
