/**
 * pi-fake-secret
 *
 * Fakes real secrets with lookalike fake secrets before they reach the LLM,
 * and restores them at execution time.
 *
 * ┌─ user input ──► input hook (real → fake) ──► LLM ──► tool_call(bash) hook (fake → real) ──► bash
 *                                                                                                              │
 *  user ◄──── context hook (real → fake) ◄── LLM ◄── tool_result hook (real → fake) ◄────────────┘
 *
 * The model (缸中之脑) only ever sees fake secrets. The harness maintains
 * a mapping table and does the swap at the bridge boundary.
 */

import { createHash } from "node:crypto";

// =============================================================================
// Constants
// =============================================================================

/**
 * Maximum single regex scan window.
 * Large text is scanned in overlapping windows instead of being passed through.
 */
export const MAX_SCAN_SIZE = 1_048_576;
const SCAN_OVERLAP = 8192;

// =============================================================================
// Types
// =============================================================================

export interface SecretMapping {
  real: string;
  fake: string;
}

interface SecretChange {
  type: "mask" | "unmask";
  hint: string;
}

interface ExtensionAPI {
  on(name: string, handler: (event: any, ctx: any) => unknown | Promise<unknown>): void;
  registerCommand(
    name: string,
    options: {
      description?: string;
      getArgumentCompletions?: (prefix: string) => Array<{ value: string; label?: string }> | null;
      handler: (args: string | undefined, ctx: any) => unknown | Promise<unknown>;
    },
  ): void;
}

// =============================================================================
const LIVE = "live";
const TEST = "test";

// Default detection patterns
// =============================================================================

export const DEFAULT_PATTERNS: RegExp[] = [
  /sk-[a-zA-Z0-9-]{20,}/g, // OpenAI API key
  /sk-ant-[a-zA-Z0-9-]{20,}/g, // Anthropic API key
  /(?:ghp|gho|ghs|ghu)_[a-zA-Z0-9]{36,}/g, // GitHub PAT v1
  /github_pat_[a-zA-Z0-9_]{82}/g, // GitHub PAT v2
  /(?:AKIA|ASIA)[A-Z0-9]{16}/g, // AWS access key
  new RegExp(`sk_${LIVE}_[a-zA-Z0-9-]{24,}`, "g"), // Stripe live key
  new RegExp(`sk_${TEST}_[a-zA-Z0-9-]{24,}`, "g"), // Stripe test key
  /xox[baprs]-[a-zA-Z0-9-]{10,}/g, // Slack token
  /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, // JWT
  /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----/g, // Private key block
  /-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----/g, // PEM key
  /AIza[a-zA-Z0-9_-]{35,}/g, // Google API key
  /glpat-[a-zA-Z0-9_-]{20,}/g, // GitLab PAT
  /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, // SendGrid key
];

// =============================================================================
// SecretStore — maintains the bidirectional mapping table
// =============================================================================

export class SecretStore {
  /** real secret value → fake */
  private realToFake = new Map<string, string>();
  /** fake → real secret value */
  private fakeToReal = new Map<string, string>();
  /** active detection patterns */
  private patterns: RegExp[] = [];

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  setPatterns(p: RegExp[]): void {
    this.patterns = p;
  }

  getPatterns(): RegExp[] {
    return this.patterns;
  }

  // ---------------------------------------------------------------------------
  // Registration
  // ---------------------------------------------------------------------------

  /**
   * Register a real secret value and return its fake.
   * Deduplicated: same real value always returns the same fake.
   */
  register(real: string): string {
    return this.registerSecret(real).fake;
  }

  private registerSecret(real: string): { fake: string; isNew: boolean } {
    const existing = this.realToFake.get(real);
    if (existing) return { fake: existing, isNew: false };

    const fake = this.generateFake(real);
    if (this.fakeToReal.has(fake) && this.fakeToReal.get(fake) !== real) {
      throw new Error("pi-fake-secret generated a duplicate fake secret");
    }
    this.realToFake.set(real, fake);
    this.fakeToReal.set(fake, real);
    return { fake, isNew: true };
  }

  /**
   * Look up the real value for a fake secret.
   * Returns undefined if the fake is unknown.
   */
  resolve(fake: string): string | undefined {
    return this.fakeToReal.get(fake);
  }

  // ---------------------------------------------------------------------------
  // Transform: mask  (replace real secrets with fake secrets)
  // ---------------------------------------------------------------------------

  /**
   * Scan text for known secret patterns, register them, and replace with
   * fake secrets. Longer matches are replaced first to avoid substring issues.
   */
  mask(text: string): string {
    return this.maskWithChanges(text).text;
  }

  maskWithChanges(text: string): { text: string; changes: SecretChange[] } {
    if (!text) return { text, changes: [] };

    if (text.length > MAX_SCAN_SIZE) {
      return this.maskLargeText(text);
    }

    // First pass: collect all unique matches from the ORIGINAL text
    const matches = new Map<string, string>(); // real → fake
    const seen = new Set<string>();
    const changes: SecretChange[] = [];

    for (const regex of this.patterns) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        const real = m[0];
        // Skip if already a known fake (re-masking would create
        // a chain of stale mappings and confuse the round-trip)
        if (this.fakeToReal.has(real)) continue;
        if (!seen.has(real) && real.length >= 8) {
          seen.add(real);
          const { fake } = this.registerSecret(real);
          matches.set(real, fake);
          changes.push({ type: "mask", hint: this.hint(real) });
        }
      }
    }

    if (matches.size === 0) return { text, changes };

    // Second pass: apply replacements (longest first to avoid partial overlaps)
    const sorted = [...matches.entries()].sort((a, b) => b[0].length - a[0].length);
    let result = text;
    for (const [real, fake] of sorted) {
      result = result.replaceAll(real, fake);
    }

    return { text: result, changes };
  }

  private maskLargeText(text: string): { text: string; changes: SecretChange[] } {
    const matches = new Map<string, string>();
    const seen = new Set<string>();
    const changes: SecretChange[] = [];
    const step = MAX_SCAN_SIZE - SCAN_OVERLAP;

    for (let start = 0; start < text.length; start += step) {
      const end = Math.min(text.length, start + MAX_SCAN_SIZE);
      const chunk = text.slice(start, end);

      for (const regex of this.patterns) {
        regex.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = regex.exec(chunk)) !== null) {
          const real = m[0];
          if (this.fakeToReal.has(real)) continue;
          if (!seen.has(real) && real.length >= 8) {
            seen.add(real);
            const { fake } = this.registerSecret(real);
            matches.set(real, fake);
            changes.push({ type: "mask", hint: this.hint(real) });
          }
        }
      }

      if (end === text.length) break;
    }

    if (matches.size === 0) return { text, changes };

    let result = text;
    const sorted = [...matches.entries()].sort((a, b) => b[0].length - a[0].length);
    for (const [real, fake] of sorted) {
      result = result.replaceAll(real, fake);
    }
    return { text: result, changes };
  }

  // ---------------------------------------------------------------------------
  // Transform: unmask  (replace known fake secrets back to real values)
  // ---------------------------------------------------------------------------

  /**
   * Replace all known fake secrets in text with the original real values.
   */
  unmask(text: string): string {
    return this.unmaskWithChanges(text).text;
  }

  unmaskWithChanges(text: string): { text: string; changes: SecretChange[] } {
    if (!text || this.fakeToReal.size === 0) return { text, changes: [] };

    let result = text;
    const changes: SecretChange[] = [];
    // Longest fake first to avoid partial matches
    const sorted = [...this.fakeToReal.entries()]
      .sort((a, b) => b[0].length - a[0].length);
    for (const [fake, real] of sorted) {
      if (result.includes(fake)) {
        result = result.replaceAll(fake, real);
        changes.push({ type: "unmask", hint: this.hint(real) });
      }
    }
    return { text: result, changes };
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  getStats() {
    return {
      patternCount: this.patterns.length,
      mappingCount: this.realToFake.size,
    };
  }

  /** Truncate a secret for display: first 4 + masked middle + last 4 chars. */
  private hint(real: string): string {
    return real.length > 8
      ? real.slice(0, 4) + "*".repeat(Math.min(12, real.length - 8)) + real.slice(-4)
      : real;
  }

  getMappings(): SecretMapping[] {
    return [...this.realToFake.entries()]
      .map(([real, fake]) => ({
        real: this.hint(real),
        fake,
      }));
  }

  // ---------------------------------------------------------------------------
  // Fake secret generation
  // ---------------------------------------------------------------------------

  /**
   * Generate a fake secret that looks indistinguishable from the original.
   *
   * Strategy: keep the structural prefix (e.g. sk-, ghp_, AKIA) unchanged so
   * the fake looks like the same type of credential. The body is derived from
   * a SHA-256 stream, not Math.random(), so the same real secret always maps
   * to the same fake. That keeps model-side history stable for provider KV
   * caches across extension reloads and session restores.
   *
   * Examples:
   *   sk-proj-AbCdEfGhIjKlMnOp1234567890
   *     → sk-proj-XyZABcDeFgHiJkLmN9876543210
   *
   *   ghp_<token-body>
   *     → ghp_<deterministic-fake-body>
   */
  private generateFake(real: string): string {
    // Find the boundary between the structural prefix and the random body:
    // take everything up to the last non-alphanumeric character that is
    // followed by at least 6 alphanumeric characters
    let splitAt = 0;
    for (let i = 0; i < real.length; i++) {
      const ch = real[i];
      // Is this a separator char?
      if (ch === "-" || ch === "_" || ch === "." || ch === "/") {
        // Check that there are enough chars after it that look like random body
        const remaining = real.length - i - 1;
        if (remaining >= 6) {
          splitAt = i + 1;
        }
      }
    }

    const prefix = real.slice(0, splitAt);
    const body = real.slice(splitAt);

    const bytes = this.hashBytes(real);
    let byteIndex = 0;
    const nextByte = () => {
      const value = bytes[byteIndex % bytes.length];
      byteIndex++;
      return value;
    };

    const fakeBody = body.split("").map((ch) => {
      if (ch >= "a" && ch <= "z")
        return String.fromCharCode(97 + (nextByte() % 26));
      if (ch >= "A" && ch <= "Z")
        return String.fromCharCode(65 + (nextByte() % 26));
      if (ch >= "0" && ch <= "9")
        return String.fromCharCode(48 + (nextByte() % 10));
      return ch;
    }).join("");

    const result = prefix + fakeBody;

    if (result === real && fakeBody.length > 0) {
      const idx = bytes[0] % fakeBody.length;
      const ch = result[splitAt + idx];
      let replacement: string;
      if (ch >= "a" && ch <= "z")
        replacement = ch === "a" ? "b" : "a";
      else if (ch >= "A" && ch <= "Z")
        replacement = ch === "A" ? "B" : "A";
      else
        replacement = ch === "0" ? "1" : "0";
      return result.slice(0, splitAt + idx) + replacement + result.slice(splitAt + idx + 1);
    }

    return result;
  }

  private hashBytes(real: string): Uint8Array {
    const chunks: number[] = [];
    let counter = 0;
    while (chunks.length < real.length) {
      const digest = createHash("sha256")
        .update("pi-fake-secret:")
        .update(real)
        .update(":")
        .update(String(counter))
        .digest();
      chunks.push(...digest);
      counter++;
    }
    return Uint8Array.from(chunks);
  }


}

// =============================================================================
// Content helpers
// =============================================================================

interface TextContentBlock {
  type: "text";
  text: string;
  [key: string]: unknown;
}

function isTextBlock(b: unknown): b is TextContentBlock {
  return (
    typeof b === "object" &&
    b !== null &&
    (b as Record<string, unknown>).type === "text" &&
    typeof (b as Record<string, unknown>).text === "string"
  );
}

/**
 * Apply a transform function to all text content blocks in an array.
 */
function transformTextBlocks(
  blocks: unknown[],
  fn: (text: string) => string,
): { blocks: unknown[]; changed: boolean } {
  let changed = false;
  const transformed = blocks.map((b) => {
    if (isTextBlock(b)) {
      const newText = fn(b.text);
      if (newText !== b.text) {
        changed = true;
        return { ...b, text: newText };
      }
    }
    return b;
  });
  return { blocks: changed ? transformed : blocks, changed };
}

/**
 * Apply a transform to all text content in a message.
 * Handles both string content and ContentBlock[] content.
 */
function transformMessageContent(
  msg: Record<string, unknown>,
  fn: (text: string) => string,
): { message: Record<string, unknown>; changed: boolean } {
  const content = msg.content;
  if (typeof content === "string") {
    const newContent = fn(content);
    return newContent !== content
      ? { message: { ...msg, content: newContent }, changed: true }
      : { message: msg, changed: false };
  }
  if (Array.isArray(content)) {
    const { blocks, changed } = transformTextBlocks(content, fn);
    return changed
      ? { message: { ...msg, content: blocks }, changed: true }
      : { message: msg, changed: false };
  }
  return { message: msg, changed: false };
}

function isToolCallEventType(toolName: string, event: { toolName?: string; name?: string; type?: string }): boolean {
  return event.toolName === toolName || event.name === toolName || event.type === toolName;
}

function transformMessageInPlaceWithChanges(
  message: Record<string, unknown>,
  fn: (text: string) => { text: string; changes: SecretChange[] },
): SecretChange[] {
  const content = message.content;
  const changes: SecretChange[] = [];

  if (typeof content === "string") {
    const transformed = fn(content);
    if (transformed.text !== content) {
      message.content = transformed.text;
      changes.push(...transformed.changes);
    }
  } else if (Array.isArray(content)) {
    for (const block of content) {
      if (isTextBlock(block)) {
        const transformed = fn(block.text);
        if (transformed.text !== block.text) {
          block.text = transformed.text;
          changes.push(...transformed.changes);
        }
      }
    }
  }

  return changes;
}

function notifySecurity(ctx: any, changes: SecretChange[], direction: "protected" | "restored"): void {
  if (!ctx.hasUI || changes.length === 0) return;

  const hints: string[] = [];
  const seen = new Set<string>();
  for (const change of changes) {
    if (!seen.has(change.hint)) {
      seen.add(change.hint);
      hints.push(change.hint);
    }
  }

  const details = hints.join(", ");
  const verb = direction === "protected" ? "已保护" : "已还原";
  const suffix = direction === "protected" ? "模型只会看到替身虚拟密钥。" : "用户侧已显示真实内容。";
  ctx.ui.notify(`pi-fake-secret: ${verb}密钥 ${details}，${suffix}`, "info");
}

// =============================================================================
// Extension entry point
// =============================================================================

export default function (pi: ExtensionAPI): void {
  const store = new SecretStore();
  store.setPatterns(DEFAULT_PATTERNS);

  // ---------------------------------------------------------------------------
  // input — intercept user messages before they reach the LLM
  // ---------------------------------------------------------------------------
  pi.on("input", async (event, ctx) => {
    if (!event.text) return { action: "continue" };

    const masked = store.maskWithChanges(event.text);
    if (masked.text === event.text) return { action: "continue" };
    notifySecurity(ctx, masked.changes, "protected");
    return { action: "transform", text: masked.text };
  });

  // ---------------------------------------------------------------------------
  // tool_call — swap fake secrets back to real values before tool executes
  // ---------------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    if (store.getStats().mappingCount === 0) return {};

    if (isToolCallEventType("bash", event)) {
      if (typeof event.input?.command === "string") {
        const restored = store.unmaskWithChanges(event.input.command);
        event.input.command = restored.text;
        notifySecurity(ctx, restored.changes, "restored");
      }
      return {};
    }

    if (isToolCallEventType("write", event)) {
      if (typeof event.input?.content === "string") {
        const restored = store.unmaskWithChanges(event.input.content);
        event.input.content = restored.text;
        notifySecurity(ctx, restored.changes, "restored");
      }
      return {};
    }

    if (isToolCallEventType("edit", event)) {
      if (Array.isArray(event.input?.edits)) {
        for (const edit of event.input.edits) {
          if (typeof edit.newText === "string") {
            const restored = store.unmaskWithChanges(edit.newText);
            edit.newText = restored.text;
            notifySecurity(ctx, restored.changes, "restored");
          }
        }
      }
      return {};
    }

    return {};
  });

  // ---------------------------------------------------------------------------
  // tool_result — intercept tool results going back to the LLM
  // ---------------------------------------------------------------------------
  pi.on("tool_result", async (event, ctx) => {
    if (!event.content || !Array.isArray(event.content)) return {};

    const changes: SecretChange[] = [];
    const { blocks, changed } = transformTextBlocks(event.content, (text) => {
      const masked = store.maskWithChanges(text);
      changes.push(...masked.changes);
      return masked.text;
    });
    if (!changed) return {};
    notifySecurity(ctx, changes, "protected");
    return { content: blocks };
  });

  // ---------------------------------------------------------------------------
  // user_bash is intentionally NOT handled — ! / !! output goes to the user's
  // terminal unchanged so they see real values. When the output enters the LLM
  // context, the context handler below fakes secrets before the next model call.
  // ---------------------------------------------------------------------------
  // context — silent full history scan before each LLM call
  // ---------------------------------------------------------------------------
  pi.on("context", async (event, _ctx) => {
    if (!event.messages || event.messages.length === 0) return;

    let changed = false;
    const messages = event.messages.map((msg: Record<string, unknown>) => {
      const transformed = transformMessageContent(msg, (text) => store.mask(text));
      if (transformed.changed) changed = true;
      return transformed.message;
    });

    if (changed) return { messages };
  });

  // ---------------------------------------------------------------------------
  // assistant messages — restore fake secrets before user-visible rendering.
  // Context is masked again by the context hook before the next model call, so
  // persisted visible messages can stay transparent to the user.
  // ---------------------------------------------------------------------------
  const restoreAssistantMessage = (event: { message?: Record<string, unknown> }, ctx: any) => {
    if (store.getStats().mappingCount === 0) return;
    if (!event.message || event.message.role !== "assistant") return;
    const changes = transformMessageInPlaceWithChanges(event.message, (text) => store.unmaskWithChanges(text));
    notifySecurity(ctx, changes, "restored");
  };

  pi.on("message_update", async (event, ctx) => {
    restoreAssistantMessage(event, ctx);
  });

  pi.on("message_end", async (event, ctx) => {
    restoreAssistantMessage(event, ctx);
  });

  // ---------------------------------------------------------------------------
  // /secret-mask command
  // ---------------------------------------------------------------------------
  pi.registerCommand("secret-mask", {
    description: "Show pi-fake-secret status and mapping table",
    getArgumentCompletions: (prefix: string) => {
      const opts = ["list", "status"].filter(c => c.startsWith(prefix));
      return opts.length > 0 ? opts.map(v => ({ value: v, label: v })) : null;
    },
    handler: async (args, ctx) => {
      const cmd = (args ?? "").trim().split(/\s+/)[0];

      if (cmd === "list") {
        const mappings = store.getMappings();
        if (mappings.length === 0) {
          ctx.ui.notify("No secrets registered yet.", "info");
          return;
        }
        const lines = mappings.map((m) => `  ${m.real}  ->  ${m.fake}`);
        ctx.ui.notify(`Secret mappings (${mappings.length}):\n${lines.join("\n")}`, "info");
        return;
      }

      const stats = store.getStats();
      ctx.ui.notify(
        `pi-fake-secret\n` +
        `  Patterns: ${stats.patternCount}\n` +
        `  Active mappings: ${stats.mappingCount}`,
        "info"
      );
    },
  });

  // ---------------------------------------------------------------------------
}
