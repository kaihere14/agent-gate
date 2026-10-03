// The Kev health check and the run-start stop. Never contacts Kev: "down" is a
// closed local port, "up" is a throwaway local HTTP server.

import { expect, test } from "bun:test"
import { execFileSync } from "node:child_process"
import { createServer } from "node:http"
import type { AddressInfo } from "node:net"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { kevReachable } from "../plugin/kev.ts"

const DOWN = "http://127.0.0.1:9/v1/systemone"
const gate = join(dirname(fileURLToPath(import.meta.url)), "..", "plugin", "gate.ts")

test("kevReachable is false when nothing listens", async () => {
  expect(await kevReachable(DOWN)).toBe(false)
})

test("kevReachable is true when any server answers, even with 404", async () => {
  const server = createServer((_req, res) => res.writeHead(404).end())
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r))
  const { port } = server.address() as AddressInfo
  try {
    expect(await kevReachable(`http://127.0.0.1:${port}/v1/systemone`)).toBe(true)
  } finally {
    server.close()
  }
})

// Own process: KEV_URL is read once when kev.ts loads, and bun test shares loaded modules across files.
test("beforeRun stops the run with setup steps when Kev is down", () => {
  const script = `const { default: p } = await import(${JSON.stringify(gate)}); console.log(JSON.stringify(await p.hooks.beforeRun({})))`
  const env = { ...process.env, KEV_URL: DOWN, AGENT_GATE_LOG: "/dev/null", AGENTGATE_MODE: "both" }
  const res = JSON.parse(execFileSync(process.execPath, ["-e", script], { env, encoding: "utf8" }))
  expect(res.stop).toBe(true)
  expect(res.reason).toContain(DOWN)
  expect(res.reason).toContain("github.com/jaredpalmer/kev")
})
