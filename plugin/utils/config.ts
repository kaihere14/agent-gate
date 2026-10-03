// Gate settings read from the environment once, at load time.

/** both (default) | rules | kev. "kev" skips the rule check, for ablation runs. */
export type Mode = "both" | "rules" | "kev"
export const MODE: Mode = (["both", "rules", "kev"] as const).find((m) => m === process.env.AGENTGATE_MODE) ?? "both"
/** AGENTGATE_CONFIRM=deny turns Kev's confirm into a block, for unattended runs where nobody answers the prompt. */
export const CONFIRM_AS_DENY = process.env.AGENTGATE_CONFIRM === "deny"
