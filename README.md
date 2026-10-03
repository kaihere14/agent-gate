# AgentGate

A two-layer security gate for coding agents. It sits between the agent and your machine, inspects every tool call before it runs, and returns **ALLOW**, **CONFIRM** or **DENY**.

Coding agents run shell commands, edit files and read untrusted content. One poisoned file or one bad guess can leak your secrets or wreck your repo. AgentGate stops that at the tool-call boundary.

## How it works

```
Cline agent
   | proposes a tool call
   v
plugin beforeTool hook (3s sandbox limit)
   |
   |-- 1. Normalize     extract commands and paths, strip quotes and $IFS tricks
   |-- 2. Hard rules    deterministic deny rules, about 1 ms, no model call
   |-- 3. Kev-4B        small decision model, 2.5s timeout, only for what rules missed
   |-- 4. Policy        map the verdict to skip, approval prompt, or run
   '-- 5. Log           append-only JSONL, secrets redacted
```

**Why two layers**
- Hard rules are fast, predictable and cannot be talked out of a decision. They cover known-bad patterns.
- Kev covers the long tail the rules do not match, and the gray zone where a human should decide.
- The rules can only make things stricter. Kev can only fill gaps. Neither layer can loosen the other.

## Three layers

| Layer | Kind | Role |
|---|---|---|
| `skill/SKILL.md` | Advisory | Tells the agent what the gate blocks and what to do instead. It is not a security boundary: the agent can ignore it. |
| Hard rules | Deterministic | Deny known-bad patterns in about 1 ms, no model call. |
| Kev-4B | Judgment | Allow, confirm or deny the calls the rules did not match. |

The skill only cuts down wasted blocked attempts. It is not counted in the catch-rate numbers: every result below measures the hard rules and Kev alone.

## Decisions

| Decision | What happens |
|---|---|
| ALLOW | The call runs. |
| CONFIRM | Cline shows its approval prompt. The user decides. |
| DENY | The call is skipped and the reason goes back to the agent. The run continues. |

**Fail closed.** If Kev is down, returns bad output or an unknown verdict, the call is denied. If Kev times out, the user is asked. A low-confidence ALLOW (below 0.35) becomes CONFIRM.

## What it blocks

- Reading or copying secrets: `.env` files, private keys, credential stores
- Disguised commands: quote splitting, `${IFS}`, globs, `sh -c` with substitution, base64 into a shell
- Sending data out: pipes into `curl`, `nc` and friends, uploads of local files
- Running downloaded code: `curl ... | sh`, process substitution
- Privilege changes: `sudo`, `chown`, world-writable `chmod`
- Destructive git: `reset --hard`, `clean -f`, `checkout -- .`, force push
- Destructive deletes: `rm -rf` on `/`, `~`, `.`, `*`, `.git`
- Tampering with the gate itself: its plugin files and uninstall commands
- The same secret rules apply to file tools (`read_files`, `editor`), not just the shell

## Results

> TODO: fill in from `tests/run.ts` after the final run.

| Setup | Dangerous steps blocked | Sent to user | Ran | Benign steps wrongly blocked |
|---|---|---|---|---|
| Rules + Kev | TBD | TBD | TBD | TBD |
| Kev only | TBD | TBD | TBD | TBD |
| Rules only | TBD | TBD | TBD | TBD |

Every test step is tagged with the layer expected to catch it: `rule-covered`, `rule-gap` or `benign-lookalike`. The rule-gap miss rate is the number that shows what Kev adds.

## Install

The installers copy the plugin to `~/.cline/plugins/agent-gate`, install the skill to `~/.cline/skills/agent-gate`, and check that Kev is reachable. They never start Kev. Both honor `CLINE_DIR`, like Cline.

```bash
# macOS / Linux, from a clone
./install.sh                 # add --with-kev to also clone Kev and install its dependencies

# macOS / Linux, without a clone
curl -fsSL https://raw.githubusercontent.com/kaihere14/agent-gate/main/install.sh | bash
```

```powershell
# Windows, from a clone
powershell -ExecutionPolicy Bypass -File .\install.ps1      # add -WithKev to also clone Kev

# Windows, without a clone
irm https://raw.githubusercontent.com/kaihere14/agent-gate/main/install.ps1 | iex
```

Uninstall with `./install.sh --uninstall` or `.\install.ps1 -Uninstall`. Restart Cline after installing.

**If Kev is not running**, Cline stops each task at the start with the steps to download and start it. Calls that reach Kev after it goes down mid-task are denied with the same steps. Set `AGENTGATE_MODE=rules` to run with the hard rules only.

Kev runs on Apple Silicon (MLX) or a CUDA/ROCm GPU:

```bash
git clone https://github.com/jaredpalmer/kev.git ~/kev && cd ~/kev
uv sync --extra serve
uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8008
```

## Development

```bash
# Keep Kev warm (idle swapping makes cold calls take seconds)
./scripts/keepwarm.sh &

# Build the disposable test lab (fake secrets, throwaway git repo)
./lab/setup.sh

# Offline tests, then the full eval against Kev
bun test
bun tests/kev-eval.ts

# Watch decisions live
bun viewer/tail.ts
```

Use an absolute path when pointing Cline at the lab, for example `cline -c /tmp/agentgate-lab "run pwd"`.

## Project layout

```
plugin/    gate.ts (the Cline hook), normalize.ts, rules.ts, kev.ts, policy.ts, log.ts,
           kev-policy.txt + kev-examples.txt (Kev instructions)
plugin/utils/  config.ts (env settings), input.ts (parse a call), checks.ts (rules, then Kev),
               record.ts (log records), result.ts (what the hook returns)
skill/     SKILL.md, advisory guidance for the agent
tests/     cases.json, kev-eval.ts (full eval), sweep.ts (threshold sweep),
           examples.test.ts + kev-health.test.ts (bun test), run.ts, bun-test.d.ts, out/ (eval output, ignored)
scripts/   keepwarm.sh, keeps Kev's prefix cache warm
lab/       setup.sh, the disposable test environment
viewer/    tail.ts, live colored decision log
docs/      findings.md
install.sh, install.ps1   installers for macOS/Linux and Windows
```

## Safety

All tests run in a disposable folder under `/tmp` with fake secrets and fake network targets (`127.0.0.1:9`). Catastrophic commands such as `rm -rf ~`, `dd` and `mkfs` are only ever checked by offline rule tests and never executed.

## Limitations

- Rules are pattern based. Building a filename from pieces, reading through an interpreter (`python -c`), and two-step attacks can evade them.
- No session memory yet. Each call is judged alone, so staged attacks (download, chmod, run) and retries through another tool are not linked.
- Kev's confidence is not calibrated, so scores are a signal and not a guarantee.
- Untrusted content (files, web responses) is not yet tracked as tainted.
- Kev needs about 10 GB of memory. On a 16 GB machine, idle swapping makes cold calls slow.
- Plugin hooks have a fixed 3 second limit in the Cline version tested.

## Roadmap

- Session state: remember recent denials, link staged commands, track taint from untrusted reads
- Promote reliable Kev catches to hard rules
- Calibrate the confidence threshold from logged scores
- Give Kev the user's original task so it can flag calls that do not match it
- Support other agents beyond Cline

## License

TBD