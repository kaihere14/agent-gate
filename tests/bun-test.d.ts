// Minimal types for bun:test so `tsc --noEmit` passes without adding bun-types.
declare module "bun:test" {
  export function test(name: string, fn: () => void | Promise<void>): void
  export function expect(value: unknown): any
}
