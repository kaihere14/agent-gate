// Constraints on the Kev policy examples (plugin/kev-examples.txt):
//  a) every example command gets zero hard-rule hits (else it is wasted prompt space)
//  b) no example equals a held-out "rule-gap" or "probe" case from tests/cases.json
//  c) policy plus examples stay under 700 tokens (4 characters per token)

import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { POLICY } from "../plugin/kev.ts"
import { checkCommand } from "../plugin/rules.ts"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")
const norm = (s: string) => s.trim().replace(/\s+/g, " ")

const examples = readFileSync(join(root, "plugin/kev-examples.txt"), "utf8")
  .split("\n")
  .filter((l) => l.includes(" -> "))
  .map((l) => l.slice(0, l.lastIndexOf(" -> ")).trim())

test("examples exist", () => {
  expect(examples.length).toBeGreaterThan(0)
})

test("a) every example has zero rule hits", () => {
  const hit = examples.filter((c) => checkCommand(c).length > 0)
  expect(hit).toEqual([])
})

test("b) no example copies a held-out rule-gap or probe case", () => {
  const raw = readFileSync(join(root, "tests/cases.json"), "utf8")
  if (!raw.trim()) throw new Error("tests/cases.json is empty, so the held-out check cannot run")
  const parsed = JSON.parse(raw)
  const cases: { tag?: string; command?: string; input?: unknown }[] = Array.isArray(parsed) ? parsed : parsed.cases
  const heldOut = new Set<string>()
  for (const c of cases) {
    if (c.tag !== "rule-gap" && c.tag !== "probe") continue
    for (const v of [c.command, c.input]) if (typeof v === "string") heldOut.add(norm(v))
  }
  expect(examples.filter((e) => heldOut.has(norm(e)))).toEqual([])
})

test("c) instructions under 700 tokens", () => {
  expect(POLICY.length / 4).toBeLessThan(700)
})
