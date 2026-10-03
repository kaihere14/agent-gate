// Hard deny rules for AgentGate.
//
// Every rule here is something a coding agent should almost never do on its
// own: reading secrets, disguising commands, sending data out, running
// downloaded code, escalating privileges, destroying history or files, or
// disabling the gate. A match means DENY with no model call. Gray-zone
// behavior is deliberately left out: that is Kev's job, and a false positive
// here cannot be overridden.
//
// Rules can only make a decision stricter. They never return ALLOW.
//
// Commands are checked in two forms: the raw string, and a flattened form
// with quotes, backslashes and $IFS removed (`c'a't .e"n"v` -> `cat .env`).
// File tool paths must be resolved to absolute paths by the caller.

import { homedir } from "node:os"

export type Category =
  | "secrets"
  | "obfuscation"
  | "exfiltration"
  | "remote-code"
  | "privilege"
  | "git"
  | "destructive"
  | "persistence"
  | "tamper"

export interface RuleHit {
  rule: string
  category: Category
  reason: string
}

export type Access = "read" | "write"

/** A command split at ; & | ( ) ` and $( with wrappers like sudo/env stripped. */
export interface Segment {
  /** Basename of the command being run, e.g. "rm" for "/bin/rm". */
  cmd: string
  args: string[]
  /** Wrappers that were stripped in front of the command, e.g. ["sudo"]. */
  via: string[]
}

export interface CommandInput {
  raw: string
  flat: string
  segments: Segment[]
  /** The command split at ; && || and newlines, in raw and flattened form. Text rules run per chain. */
  chains: { raw: string; flat: string; length: number }[]
}

interface CommandRule {
  id: string
  category: Category
  reason: string
  test: (c: CommandInput) => boolean
}

interface PathRule {
  id: string
  category: Category
  reason: string
  access: Access | "any"
  pattern: RegExp
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/** Undo the cheap disguises: quote splitting, backslash escapes, $IFS. */
export function flatten(command: string): string {
  return command
    .replace(/\$\{?IFS\}?/g, " ")
    .replace(/\\(?=[^\n])/g, "")
    .replace(/['"]/g, "")
}

const WRAPPERS = new Set([
  "sudo", "doas", "nohup", "time", "command", "builtin", "exec", "nice", "caffeinate", "stdbuf",
])
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"])
const XARGS_FLAGS_WITH_VALUE = new Set(["-I", "-n", "-P", "-L", "-d", "-E", "-s"])

function basename(word: string): string {
  return word.slice(word.lastIndexOf("/") + 1)
}

export function segments(flat: string): Segment[] {
  const out: Segment[] = []
  for (const part of flat.split(/\$\(|[;&|()`\n]/)) {
    const words = part.trim().split(/\s+/).filter(Boolean)
    const via: string[] = []
    let i = 0
    while (i < words.length) {
      const w = words[i]
      const name = basename(w)
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) {
        i++
      } else if (WRAPPERS.has(name)) {
        via.push(name)
        i++
        while (i < words.length && words[i].startsWith("-")) i++
      } else if (name === "env") {
        via.push(name)
        i++
        while (i < words.length && (words[i].startsWith("-") || words[i].includes("="))) i++
      } else if (name === "timeout") {
        via.push(name)
        i++
        while (i < words.length && words[i].startsWith("-")) i++
        i++ // duration
      } else if (name === "xargs") {
        via.push(name)
        i++
        while (i < words.length && words[i].startsWith("-")) {
          i += XARGS_FLAGS_WITH_VALUE.has(words[i]) ? 2 : 1
        }
      } else if (SHELLS.has(name) && /^-\w*c\w*$/.test(words[i + 1] ?? "")) {
        // `bash -c "rm -rf /"` once flattened is `bash -c rm -rf /`
        via.push(name)
        i += 2
      } else {
        break
      }
    }
    if (i < words.length) out.push({ cmd: basename(words[i]), args: words.slice(i + 1), via })
  }
  return out
}

const HOME = homedir()

function expandHome(p: string): string {
  return p.replace(/^(?:~|\$\{?HOME\}?)(?=\/|$)/, HOME)
}

function stripSlashes(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, "") : p
}

/** Short flags may be bundled: hasFlag(["-rf"], "r") is true. */
function hasShortFlag(args: string[], letters: string): boolean {
  return args.some((a) => /^-[A-Za-z]+$/.test(a) && [...letters].some((l) => a.includes(l)))
}

function hasLongFlag(args: string[], ...names: string[]): boolean {
  return args.some((a) => names.some((n) => a === n || a.startsWith(n + "=")))
}

function positional(args: string[]): string[] {
  const out: string[] = []
  let afterDashDash = false
  for (const a of args) {
    if (!afterDashDash && a === "--") afterDashDash = true
    else if (afterDashDash || !a.startsWith("-")) out.push(a)
  }
  return out
}

function anyText(c: CommandInput, pattern: RegExp): boolean {
  return c.chains.some((ch) => pattern.test(ch.raw) || pattern.test(ch.flat))
}

/** Longest single chain the text rules will scan. Longer ones are denied (see obfuscation-oversized). */
export const MAX_CHAIN = 8_192

const DECODER_IN_SUBSTITUTION = /^[^)`]{0,300}?(?:base64|xxd|\brev\b|curl|wget|printf\s+\S*\\x)/i

/** eval / sh -c whose $(...) or `...` runs a decoder or downloader. Bounded scan, no backtracking blowup. */
function evalsDecodedPayload(text: string): boolean {
  if (!/\beval\b|\b(?:ba|z|da|k)?sh\s+-\w*c/.test(text)) return false
  for (const m of text.matchAll(/\$\(|`/g)) {
    const start = (m.index ?? 0) + m[0].length
    if (DECODER_IN_SUBSTITUTION.test(text.slice(start, start + 300))) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Shared pattern pieces
// ---------------------------------------------------------------------------

const NET_TOOLS = "curl|wget|nc|ncat|netcat|socat|telnet|ssh|ftp|tftp|sftp"
const INTERPRETERS = "(?:ba|z|da|k|fi)?sh|python[0-9.]*|perl|ruby|node|bun|deno|php|osascript|pwsh|powershell"
const PIPE_TO_INTERPRETER = `\\|\\s*(?:sudo\\s+)?(?:[\\w.~-]*/)*(?:${INTERPRETERS})\\b`

/** Top-level directories whose recursive deletion is never a coding task. */
const PROTECTED_DIRS = new Set([
  "/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*",
  ".", "./", "./*", "..", "../", "*", ".*", ".git", "./.git",
  HOME, `${HOME}/*`,
  "/Users", "/home", "/root", "/etc", "/usr", "/bin", "/sbin", "/lib", "/var", "/opt",
  "/System", "/Library", "/Applications", "/private", "/boot", "/dev", "/proc", "/sys",
])

function isProtectedTarget(arg: string): boolean {
  return PROTECTED_DIRS.has(arg) || PROTECTED_DIRS.has(stripSlashes(arg)) || PROTECTED_DIRS.has(expandHome(stripSlashes(arg)))
}

// ---------------------------------------------------------------------------
// Secret locations. Shared by command rules and file tool path rules.
// `B` is the left boundary: start, whitespace, slash, quote or an operator.
// ---------------------------------------------------------------------------

const B = `(?:^|[\\s/'"=:<>(])`
const END = `(?=$|[\\s'";|&)<>*?\\[\\]])`

const SECRET_PATHS: { id: string; reason: string; pattern: RegExp }[] = [
  {
    id: "secret-dotenv",
    reason: "reads or copies a .env file",
    pattern: new RegExp(
      `${B}\\.env(?:rc)?(?!\\.(?:example|sample|template|dist|defaults?|schema)${END})(?:\\.[\\w.-]+)?${END}`,
    ),
  },
  {
    id: "secret-ssh-key",
    reason: "accesses SSH private keys",
    pattern: new RegExp(
      `${B}id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?!\\.pub)${END}|\\.ssh(?:/(?!(?:known_hosts|config|authorized_keys)${END}|[\\w.-]+\\.pub${END})[^\\s'"]*)?${END}`,
    ),
  },
  {
    id: "secret-key-file",
    reason: "accesses a private key or certificate bundle",
    pattern: new RegExp(`\\.(?:pem|p12|pfx|jks|keystore|ppk)${END}|${B}[\\w.-]*private[_-]?key[\\w.-]*${END}`, "i"),
  },
  {
    id: "secret-cloud-credentials",
    reason: "reads cloud or cluster credentials",
    pattern:
      /\.aws\/(?:credentials|config)\b|\.config\/gcloud\/(?:credentials|application_default_credentials|access_tokens|legacy_credentials)|\.azure\/(?:accessTokens|msal_token_cache|azureProfile)|\.kube\/config\b|\.docker\/config\.json\b|\.terraform\.d\/credentials|\.oci\/config\b/,
  },
  {
    id: "secret-token-store",
    reason: "reads a stored token or password file",
    pattern: new RegExp(
      `${B}\\.(?:netrc|pgpass|pypirc|git-credentials|vault-token|my\\.cnf)${END}|(?:~|\\$\\{?HOME\\}?|/Users/[^/\\s]+|/home/[^/\\s]+)/\\.npmrc${END}|\\.config/gh/hosts\\.yml|\\.cline/data/settings/providers\\.json`,
    ),
  },
  {
    id: "secret-system-store",
    reason: "reads the system password or keychain store",
    pattern:
      /\/etc\/(?:shadow|gshadow|master\.passwd)\b|Library\/Keychains\b|\.(?:keychain|keychain-db)\b|(?:Google\/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox|Mozilla)[^;|&]*(?:Cookies|Login Data|logins\.json|key[34]\.db|Web Data)/,
  },
]

// The gate's own files, settings and log. Reading is fine; changing is not.
const GATE_PATH = /\.cline\/plugins\b|agent-gate|\.cline\/data\/settings\/global-settings\.json/

const READ_ONLY_CMDS = new Set([
  "cat", "less", "more", "head", "tail", "ls", "grep", "egrep", "rg", "ag", "wc", "stat", "file", "bat",
  "diff", "tree", "du", "realpath", "readlink", "md5", "md5sum", "shasum", "sha256sum", "bun", "node",
  "tsc", "npx", "echo", "printf", "pwd", "cd", "test", "[",
])

// ---------------------------------------------------------------------------
// Command rules
// ---------------------------------------------------------------------------

export const COMMAND_RULES: CommandRule[] = [
  // --- secrets -------------------------------------------------------------
  ...SECRET_PATHS.map(
    (s): CommandRule => ({ id: s.id, category: "secrets", reason: s.reason, test: (c) => anyText(c, s.pattern) }),
  ),
  {
    id: "secret-keychain-cli",
    category: "secrets",
    reason: "dumps passwords from the OS keychain",
    test: (c) =>
      c.segments.some(
        (s) =>
          (s.cmd === "security" &&
            /^(?:find-(?:generic|internet)-password|dump-keychain|export|find-certificate)$/.test(s.args[0] ?? "")) ||
          (s.cmd === "secret-tool" && s.args[0] === "lookup"),
      ),
  },

  // --- obfuscation ---------------------------------------------------------
  {
    id: "obfuscation-ifs",
    category: "obfuscation",
    reason: "uses $IFS to hide spaces in a command",
    test: (c) => /\$\{?IFS\}?/.test(c.raw),
  },
  {
    id: "obfuscation-quote-split",
    category: "obfuscation",
    reason: "splits a word with quotes to evade matching (e.g. c'a't)",
    test: (c) => /[A-Za-z0-9_.-](?:''|""|'[A-Za-z0-9_./-]+'|"[A-Za-z0-9_./-]+")[A-Za-z0-9_.-]/.test(c.raw),
  },
  {
    id: "obfuscation-secret-glob",
    category: "obfuscation",
    reason: "uses a glob that targets secret files (e.g. .e*, id_*)",
    test: (c) => anyText(c, new RegExp(`${B}(?:\\.e[nv]{0,2}|\\.s[sh]{0,2}|id_[a-z0-9]*|\\.aw[s]?|\\.net[rc]{0,2})[*?\\[]`)),
  },
  {
    id: "obfuscation-decoded-exec",
    category: "obfuscation",
    reason: "decodes a payload and runs it",
    test: (c) =>
      anyText(
        c,
        new RegExp(
          `(?:base64\\s+(?:-\\w*[dD]\\w*|--decode)|xxd\\s+-r\\w*|openssl\\s+(?:base64|enc)\\b[^|;&]*-d\\b|\\brev\\b|printf\\s+\\S*\\\\x[0-9a-f]{2})[^;&]*${PIPE_TO_INTERPRETER}`,
          "i",
        ),
      ) || c.chains.some((ch) => evalsDecodedPayload(ch.raw) || evalsDecodedPayload(ch.flat)),
  },
  {
    id: "obfuscation-oversized",
    category: "obfuscation",
    reason: `has a single command chain longer than ${MAX_CHAIN} characters, too long to inspect`,
    test: (c) => c.chains.some((ch) => ch.length > MAX_CHAIN),
  },

  // --- exfiltration --------------------------------------------------------
  {
    id: "exfil-pipe-to-network",
    category: "exfiltration",
    reason: "pipes local data into a network tool",
    test: (c) => anyText(c, new RegExp(`\\|\\s*(?:sudo\\s+)?(?:[\\w.~-]*/)*(?:${NET_TOOLS})\\b`)),
  },
  {
    id: "exfil-upload-file",
    category: "exfiltration",
    reason: "uploads a local file to a remote server",
    test: (c) =>
      c.segments.some((s) => {
        const a = s.args.join(" ")
        if (s.cmd === "curl") {
          return (
            /(?:^|\s)(?:-d|--data(?:-binary|-raw|-ascii)?|--json)\s*=?\s*@(?!-\b)/.test(a) ||
            /(?:^|\s)(?:-F|--form)\s*\S+=@/.test(a) ||
            /(?:^|\s)(?:-T|--upload-file)\b/.test(a)
          )
        }
        if (s.cmd === "wget") return /--(?:post|body)-file\b/.test(a)
        return false
      }),
  },
  {
    id: "exfil-raw-socket",
    category: "exfiltration",
    reason: "opens a raw network socket from the shell",
    test: (c) =>
      anyText(c, /\/dev\/(?:tcp|udp)\//) ||
      c.segments.some((s) => ["nc", "ncat", "netcat"].includes(s.cmd) && /<\s*\S/.test(c.flat)),
  },

  // --- running downloaded code ---------------------------------------------
  {
    id: "remote-pipe-to-shell",
    category: "remote-code",
    reason: "pipes downloaded content straight into an interpreter",
    test: (c) => anyText(c, new RegExp(`\\b(?:curl|wget|fetch|http|aria2c)\\b[^;&]*${PIPE_TO_INTERPRETER}`)),
  },
  {
    id: "remote-process-substitution",
    category: "remote-code",
    reason: "runs downloaded content through process or command substitution",
    test: (c) =>
      anyText(
        c,
        new RegExp(
          `(?:\\b(?:${INTERPRETERS})|\\bsource|(?:^|[\\s;&|])\\.)\\s+(?:-\\S+\\s+)*<\\(\\s*(?:[\\w.~-]*/)*(?:curl|wget)\\b`,
        ),
      ) || anyText(c, new RegExp(`\\b(?:${INTERPRETERS})\\s+(?:-\\S+\\s+)*-\\w*[ce]\\w*\\s+["']?(?:\\$\\(|\`)\\s*(?:curl|wget)\\b`)),
  },

  // --- privilege -----------------------------------------------------------
  {
    id: "privilege-escalation",
    category: "privilege",
    reason: "runs a command as root or another user",
    test: (c) =>
      c.segments.some(
        (s) =>
          s.via.some((v) => v === "sudo" || v === "doas") ||
          ["sudo", "doas", "su", "pkexec", "runas", "visudo"].includes(s.cmd),
      ),
  },
  {
    id: "privilege-chown",
    category: "privilege",
    reason: "changes file ownership",
    test: (c) => c.segments.some((s) => s.cmd === "chown" || s.cmd === "chgrp"),
  },
  {
    id: "privilege-chmod-unsafe",
    category: "privilege",
    reason: "makes files world-writable or setuid/setgid",
    test: (c) =>
      c.segments.some((s) => {
        if (s.cmd !== "chmod") return false
        return s.args.some((a) => {
          if (/^[0-7]{3,4}$/.test(a)) {
            const other = Number(a[a.length - 1])
            const special = a.length === 4 ? Number(a[0]) : 0
            return (other & 2) !== 0 || (special & 6) !== 0
          }
          return a
            .split(",")
            .some((clause) => /^[ugoa]*[ao][ugoa]*[+=][rwxXt]*w/.test(clause) || /^[ugoa]*[+=][rwxXt]*s/.test(clause))
        })
      }),
  },

  // --- destructive git -----------------------------------------------------
  {
    id: "git-destructive",
    category: "git",
    reason: "discards work or rewrites history with git",
    test: (c) =>
      c.segments.some((s) => {
        if (s.cmd !== "git") return false
        // Skip global options: git -C dir -c k=v --no-pager <sub> ...
        let i = 0
        while (i < s.args.length && s.args[i].startsWith("-")) {
          i += ["-C", "-c", "--git-dir", "--work-tree", "--namespace"].includes(s.args[i]) ? 2 : 1
        }
        const sub = s.args[i]
        const rest = s.args.slice(i + 1)
        const targets = positional(rest)
        const wide = targets.some((t) => t === "." || t === "./" || t === "*" || t === ":/" || t === ":")
        switch (sub) {
          case "reset":
            return hasLongFlag(rest, "--hard", "--merge")
          case "clean":
            return (
              (hasShortFlag(rest, "f") || hasLongFlag(rest, "--force")) &&
              !hasShortFlag(rest, "n") &&
              !hasLongFlag(rest, "--dry-run")
            )
          case "checkout":
            return wide || hasShortFlag(rest, "f") || hasLongFlag(rest, "--force")
          case "restore":
            return wide && (!hasLongFlag(rest, "--staged") || hasLongFlag(rest, "--worktree"))
          case "push":
            return (
              hasShortFlag(rest, "f") ||
              hasLongFlag(rest, "--force", "--force-with-lease", "--force-if-includes", "--mirror") ||
              targets.some((t) => t.startsWith("+"))
            )
          case "stash":
            return rest[0] === "clear"
          case "reflog":
            return rest[0] === "expire" || rest[0] === "delete"
          case "filter-branch":
          case "filter-repo":
            return true
          default:
            return false
        }
      }),
  },

  // --- destructive filesystem / system -------------------------------------
  {
    id: "destructive-rm-root",
    category: "destructive",
    reason: "recursively deletes a home, root, project or .git directory",
    test: (c) =>
      c.segments.some(
        (s) =>
          s.cmd === "rm" &&
          (hasShortFlag(s.args, "rR") || hasLongFlag(s.args, "--recursive")) &&
          positional(s.args).some(isProtectedTarget),
      ),
  },
  {
    id: "destructive-find-delete",
    category: "destructive",
    reason: "bulk-deletes from a home or root directory with find",
    test: (c) =>
      c.segments.some(
        (s) =>
          s.cmd === "find" &&
          s.args.length > 0 &&
          isProtectedTarget(s.args[0]) &&
          s.args[0] !== "." &&
          s.args[0] !== "./" &&
          (s.args.includes("-delete") || /-exec(?:dir)?\s+(?:[\w.~-]*\/)*rm\b/.test(s.args.join(" "))),
      ),
  },
  {
    id: "destructive-disk",
    category: "destructive",
    reason: "writes to or erases a raw disk",
    test: (c) =>
      c.segments.some(
        (s) =>
          (s.cmd === "dd" && s.args.some((a) => /^of=\/dev\/(?!null$|zero$|stdout$|stderr$)/.test(a))) ||
          /^mkfs(?:\.\w+)?$/.test(s.cmd) ||
          ["wipefs", "fdisk", "sfdisk", "parted", "newfs_apfs", "newfs_hfs"].includes(s.cmd) ||
          (s.cmd === "diskutil" &&
            /^(?:eraseDisk|eraseVolume|partitionDisk|zeroDisk|secureErase|randomDisk|reformat)$/.test(s.args[0] ?? "")),
      ) || anyText(c, />\s*\/dev\/(?:sd[a-z]|hd[a-z]|nvme\d|disk\d|rdisk\d|mmcblk\d)/),
  },
  {
    id: "destructive-shred",
    category: "destructive",
    reason: "irrecoverably overwrites files",
    test: (c) => c.segments.some((s) => s.cmd === "shred" || (s.cmd === "srm" && s.args.length > 0)),
  },
  {
    id: "destructive-fork-bomb",
    category: "destructive",
    reason: "fork bomb",
    test: (c) => anyText(c, /(?:^|[\s;&|])([A-Za-z_][\w-]{0,30}|:)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}/),
  },
  {
    id: "destructive-power",
    category: "destructive",
    reason: "shuts down or reboots the machine",
    test: (c) =>
      c.segments.some(
        (s) =>
          ["shutdown", "reboot", "halt", "poweroff"].includes(s.cmd) ||
          (s.cmd === "systemctl" && /^(?:poweroff|reboot|halt|suspend)$/.test(s.args[0] ?? "")),
      ),
  },
  {
    id: "destructive-kill-all",
    category: "destructive",
    reason: "kills every process the user owns",
    test: (c) => c.segments.some((s) => s.cmd === "kill" && s.args.includes("-1")),
  },
  {
    id: "destructive-crontab-wipe",
    category: "destructive",
    reason: "deletes the user's crontab",
    test: (c) => c.segments.some((s) => s.cmd === "crontab" && hasShortFlag(s.args, "r")),
  },
  {
    id: "destructive-disable-os-security",
    category: "destructive",
    reason: "turns off operating system security protections",
    test: (c) =>
      c.segments.some(
        (s) =>
          (s.cmd === "csrutil" && s.args[0] === "disable") ||
          (s.cmd === "spctl" && hasLongFlag(s.args, "--master-disable", "--global-disable")) ||
          (s.cmd === "setenforce" && s.args[0] === "0") ||
          (s.cmd === "ufw" && s.args[0] === "disable"),
      ),
  },

  // --- persistence ---------------------------------------------------------
  {
    id: "persistence-authorized-keys",
    category: "persistence",
    reason: "adds an SSH key that grants remote login",
    test: (c) => anyText(c, /(?:>>?|\btee\b|\bcp\b|\bmv\b)[^;|&]*authorized_keys/) || anyText(c, /\bssh-copy-id\b/),
  },
  {
    id: "persistence-launch-agent",
    category: "persistence",
    reason: "installs a background service that starts at login",
    test: (c) =>
      anyText(c, /(?:>>?|\btee\b|\bcp\b|\bmv\b|\bln\b)[^;|&]*Library\/Launch(?:Agents|Daemons)\//) ||
      c.segments.some((s) => s.cmd === "launchctl" && /^(?:load|bootstrap|enable|submit)$/.test(s.args[0] ?? "")),
  },

  // --- tampering with the gate ---------------------------------------------
  {
    id: "tamper-gate-files",
    category: "tamper",
    reason: "modifies, moves or deletes AgentGate's own files, settings or log",
    test: (c) =>
      anyText(c, new RegExp(`>>?\\s*\\S*(?:${GATE_PATH.source})`)) ||
      c.segments.some(
        (s) =>
          !READ_ONLY_CMDS.has(s.cmd) &&
          !(s.cmd === "find" && !s.args.some((a) => a === "-delete" || a.startsWith("-exec"))) &&
          !(s.cmd === "sed" && !s.args.some((a) => /^-\w*i/.test(a) || a.startsWith("--in-place"))) &&
          !(s.cmd === "git" && /^(?:status|log|diff|show|blame)$/.test(s.args[0] ?? "")) &&
          s.args.some((a) => GATE_PATH.test(a)),
      ),
  },
  {
    id: "tamper-gate-uninstall",
    category: "tamper",
    reason: "uninstalls or disables Cline plugins",
    test: (c) =>
      c.segments.some(
        (s) =>
          s.cmd === "cline" &&
          s.args[0] === "plugin" &&
          /^(?:uninstall|remove|rm|disable)$/.test(s.args[1] ?? ""),
      ),
  },
]

// ---------------------------------------------------------------------------
// Path rules (read_files, editor, and any other tool that takes a path)
// ---------------------------------------------------------------------------

export const PATH_RULES: PathRule[] = [
  ...SECRET_PATHS.map((s): PathRule => ({ id: s.id, category: "secrets", reason: s.reason, access: "any", pattern: s.pattern })),
  {
    id: "tamper-gate-files",
    category: "tamper",
    reason: "modifies AgentGate's own files, settings or log",
    access: "write",
    pattern: GATE_PATH,
  },
  {
    id: "persistence-authorized-keys",
    category: "persistence",
    reason: "adds an SSH key that grants remote login",
    access: "write",
    pattern: /\.ssh\/authorized_keys\d?$/,
  },
  {
    id: "persistence-launch-agent",
    category: "persistence",
    reason: "installs a background service that starts at login",
    access: "write",
    pattern: /Library\/Launch(?:Agents|Daemons)\//,
  },
  {
    id: "privilege-system-file",
    category: "privilege",
    reason: "writes to a system configuration file",
    access: "write",
    pattern: /^\/(?:etc|private\/etc|System|usr\/(?!local\/)|bin|sbin)\//,
  },
]

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

export function parseCommand(command: string): CommandInput {
  const flat = flatten(command)
  const chains = command
    .split(/;|&&|\|\||\n/)
    .filter((raw) => raw.trim())
    .map((raw) => {
      // Oversized chains are denied by obfuscation-oversized; don't feed them to the regexes.
      const capped = raw.length > MAX_CHAIN ? raw.slice(0, MAX_CHAIN) : raw
      return { raw: capped, flat: flatten(capped), length: raw.length }
    })
  return { raw: command, flat, segments: segments(flat), chains }
}

/** Every hard rule a shell command matches. Empty means no rule fired. */
export function checkCommand(command: string): RuleHit[] {
  const input = parseCommand(command)
  const hits: RuleHit[] = []
  for (const r of COMMAND_RULES) {
    let matched = false
    try {
      matched = r.test(input)
    } catch {
      matched = true // a crashing rule fails closed
    }
    if (matched) hits.push({ rule: r.id, category: r.category, reason: r.reason })
  }
  return hits
}

/** Every hard rule a file path matches for the given access. Pass absolute paths. */
export function checkPath(path: string, access: Access): RuleHit[] {
  const p = expandHome(path)
  return PATH_RULES.filter((r) => (r.access === "any" || r.access === access) && r.pattern.test(p)).map((r) => ({
    rule: r.id,
    category: r.category,
    reason: r.reason,
  }))
}
