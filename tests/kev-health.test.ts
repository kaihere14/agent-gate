// The Kev health check and the run-start stop. Never contacts Kev: "down" is a
// closed local port, "up" is a throwaway local HTTP server.

import { expect, test } from "bun:test"
import { createServer } from "node:http"
import type { AddressInfo } from "node:net"

const DOWN = "http://127.0.0.1:9/v1/systemone"
process.env.KEV_URL = DOWN
process.env.AGENT_GATE_LOG = "/dev/null"
const { kevReachable, KEV_SETUP_HINT } = await import("../plugin/kev.ts")
const { default: plugin } = await import("../plugin/gate.ts")

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

test("beforeRun stops the run with setup steps when Kev is down", async () => {
  const res = await (plugin.hooks as any).beforeRun({})
  expect(res.stop).toBe(true)
  expect(res.reason).toBe(KEV_SETUP_HINT)
  expect(res.reason).toContain("github.com/jaredpalmer/kev")
})
