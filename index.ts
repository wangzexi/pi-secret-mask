/**
 * pi-secret-mask
 *
 * Masks real secrets with lookalike placeholders before they reach the LLM,
 * and restores them at execution time.
 *
 * ┌─ user input ──► input hook (real → placeholder) ──► LLM ──► tool_call(bash) hook (placeholder → real) ──► bash
 *                                                                                                              │
 *  user ◄──── context hook (real → placeholder) ◄── LLM ◄── tool_result hook (real → placeholder) ◄────────────┘
 *
 * The model (缸中之脑) only ever sees placeholders. The harness maintains
 * a mapping table and does the swap at the bridge boundary.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

// =============================================================================
// Constants
// =============================================================================

/** Maximum text length to scan (1 MB). Larger content passes through unmasked. */
const MAX_SCAN_SIZE = 1_048_576;



// =============================================================================
// Types
// =============================================================================

interface SecretPattern {
  /** Human-readable name for display/logging. */
  name: string;
  /** Global regex matching the secret format. */
  regex: RegExp;
}

interface SecretMapping {
  real: string;
  placeholder: string;
}

// =============================================================================
const LIVE = "live";
const TEST = "test";

// Default detection patterns
// =============================================================================

const DEFAULT_PATTERNS: SecretPattern[] = [
  { name: "openai-api-key",       regex: /sk-[a-zA-Z0-9-]{20,}/g },
  { name: "anthropic-api-key",    regex: /sk-ant-[a-zA-Z0-9-]{20,}/g },
  { name: "github-pat-v1",        regex: /(?:ghp|gho|ghs|ghu)_[a-zA-Z0-9]{36,}/g },
  { name: "github-pat-v2",        regex: /github_pat_[a-zA-Z0-9_]{82}/g },
  { name: "aws-access-key",       regex: /(?:AKIA|ASIA)[A-Z0-9]{16}/g },
  { name: "stripe-live",          regex: new RegExp(`sk_${LIVE}_[a-zA-Z0-9-]{24,}`, "g") },
  { name: "stripe-test",          regex: new RegExp(`sk_${TEST}_[a-zA-Z0-9-]{24,}`, "g") },
  { name: "slack-token",          regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g },
  { name: "jwt",                  regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { name: "private-key-block",    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----/g },
  { name: "pem-key",              regex: /-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----/g },
  { name: "google-api-key",       regex: /AIza[a-zA-Z0-9_-]{35,}/g },
  { name: "gitlab-pat",           regex: /glpat-[a-zA-Z0-9_-]{20,}/g },
  { name: "sendgrid-key",         regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g },
];

// =============================================================================
// SecretStore — maintains the bidirectional mapping table
// =============================================================================

class SecretStore {
  /** real secret value → placeholder */
  private realToPlaceholder = new Map<string, string>();
  /** placeholder → real secret value */
  private placeholderToReal = new Map<string, string>();
  /** active detection patterns */
  private patterns: SecretPattern[] = [];
  /** accumulated changes since last beginTracking() call */
  private pendingChanges: Array<{real:string;placeholder:string;type:'mask'|'unmask'}> = [];
  private tracking = false;

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  setPatterns(p: SecretPattern[]): void {
    this.patterns = p;
  }

  getPatterns(): SecretPattern[] {
    return this.patterns;
  }

  // ---------------------------------------------------------------------------
  // Change tracking (for notifications)
  // ---------------------------------------------------------------------------

  /** Start accumulating changes. */
  beginTracking(): void {
    this.pendingChanges = [];
    this.tracking = true;
  }

  /** Collect and clear accumulated changes. */
  flushChanges(): Array<{real:string;placeholder:string;type:'mask'|'unmask'}> {
    this.tracking = false;
    const c = this.pendingChanges;
    this.pendingChanges = [];
    return c;
  }

  // ---------------------------------------------------------------------------
  // Registration
  // ---------------------------------------------------------------------------

  /**
   * Register a real secret value and return its placeholder.
   * Deduplicated: same real value always returns the same placeholder.
   */
  register(real: string): string {
    const existing = this.realToPlaceholder.get(real);
    if (existing) return existing;

    const placeholder = this.generatePlaceholder(real);
    this.realToPlaceholder.set(real, placeholder);
    this.placeholderToReal.set(placeholder, real);
    if (this.tracking) {
      this.pendingChanges.push({ real, placeholder, type: 'mask' });
    }
    return placeholder;
  }

  /**
   * Look up the real value for a placeholder.
   * Returns undefined if the placeholder is unknown.
   */
  resolve(placeholder: string): string | undefined {
    return this.placeholderToReal.get(placeholder);
  }

  // ---------------------------------------------------------------------------
  // Transform: mask  (replace real secrets with placeholders)
  // ---------------------------------------------------------------------------

  /**
   * Scan text for known secret patterns, register them, and replace with
   * placeholders. Longer matches are replaced first to avoid substring issues.
   */
  mask(text: string): string {
    if (!text || text.length > MAX_SCAN_SIZE) return text;

    // First pass: collect all unique matches from the ORIGINAL text
    const matches = new Map<string, string>(); // real → placeholder
    const seen = new Set<string>();

    for (const { regex } of this.patterns) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        const real = m[0];
        // Skip if already a known placeholder (re-masking would create
        // a chain of stale mappings and confuse the round-trip)
        if (this.placeholderToReal.has(real)) continue;
        if (!seen.has(real) && real.length >= 8) {
          seen.add(real);
          matches.set(real, this.register(real));
        }
      }
    }

    if (matches.size === 0) return text;

    // Second pass: apply replacements (longest first to avoid partial overlaps)
    const sorted = [...matches.entries()].sort((a, b) => b[0].length - a[0].length);
    let result = text;
    for (const [real, placeholder] of sorted) {
      result = result.replaceAll(real, placeholder);
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // Transform: unmask  (replace known placeholders back to real values)
  // ---------------------------------------------------------------------------

  /**
   * Replace all known placeholders in text with the original real values.
   */
  unmask(text: string): string {
    if (!text || this.placeholderToReal.size === 0) return text;

    let result = text;
    // Longest placeholder first to avoid partial matches
    const sorted = [...this.placeholderToReal.entries()]
      .sort((a, b) => b[0].length - a[0].length);
    for (const [placeholder, real] of sorted) {
      if (result.includes(placeholder)) {
        if (this.tracking) {
          this.pendingChanges.push({ real, placeholder, type: 'unmask' });
        }
        result = result.replaceAll(placeholder, real);
      }
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  getStats() {
    return {
      patternCount: this.patterns.length,
      mappingCount: this.realToPlaceholder.size,
    };
  }

  /** Truncate a secret for display: first 4 + … + last 4 chars. */
  private hint(real: string): string {
    return real.length > 8
      ? real.slice(0, 4) + "…" + real.slice(-4)
      : real;
  }

  getMappings(): SecretMapping[] {
    return [...this.realToPlaceholder.entries()]
      .map(([real, placeholder]) => ({
        real: this.hint(real),
        placeholder,
      }));
  }

  /**
   * Format a single change for notification display.
   * Mask:   🔒 sk-p…2504 → sk-proj-XyZAbCd...
   * Unmask: 🔓 sk-proj-XyZAbCd... → sk-p…2504
   */
  formatChange(c: {real:string;placeholder:string;type:'mask'|'unmask'}): string {
    if (c.type === 'mask') {
      return `🔒 ${this.hint(c.real)} → ${c.placeholder}`;
    }
    return `🔓 ${c.placeholder} → ${this.hint(c.real)}`;
  }

  // ---------------------------------------------------------------------------
  // Placeholder generation
  // ---------------------------------------------------------------------------

  /**
   * Generate a placeholder that looks indistinguishable from the original.
   *
   * Strategy: keep the first "prefix segment" (e.g. sk-, ghp_, AKIA) unchanged
   * so the placeholder looks like the same TYPE of credential. Randomize the
   * variable "body" part character by character within the same case class
   * (lowercase, uppercase, digit).
   *
   * Examples:
   *   sk-proj-AbCdEfGhIjKlMnOp1234567890
   *     → sk-proj-XyZABcDeFgHiJkLmN9876543210
   *
   *   ghp_AbCdEfGhIjKlMnOp1234567890AbCdEfGhIjKlMnOp1234
   *     → ghp_XyZABcDeFgHiJkLmN9876543210XyZABcDeFgHiJkLmN9876
   */
  private generatePlaceholder(real: string): string {
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

    // Randomize the body: same length, same character class per position
    const randomizedBody = body.split("").map((ch) => {
      if (ch >= "a" && ch <= "z")
        return String.fromCharCode(97 + Math.floor(Math.random() * 26));
      if (ch >= "A" && ch <= "Z")
        return String.fromCharCode(65 + Math.floor(Math.random() * 26));
      if (ch >= "0" && ch <= "9")
        return String.fromCharCode(48 + Math.floor(Math.random() * 10));
      return ch;
    }).join("");

    const result = prefix + randomizedBody;

    // Fallback: if by extreme luck the result equals the original, flip
    // one character in the body
    if (result === real && randomizedBody.length > 0) {
      const idx = Math.floor(Math.random() * randomizedBody.length);
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
): unknown[] {
  return blocks.map((b) => {
    if (isTextBlock(b)) {
      const newText = fn(b.text);
      return newText !== b.text ? { ...b, text: newText } : b;
    }
    return b;
  });
}

/**
 * Apply a transform to all text content in a message.
 * Handles both string content and ContentBlock[] content.
 */
function transformMessageContent(
  msg: Record<string, unknown>,
  fn: (text: string) => string,
): Record<string, unknown> {
  const content = msg.content;
  if (typeof content === "string") {
    const newContent = fn(content);
    return newContent !== content ? { ...msg, content: newContent } : msg;
  }
  if (Array.isArray(content)) {
    const newContent = transformTextBlocks(content, fn);
    return newContent !== content ? { ...msg, content: newContent } : msg;
  }
  return msg;
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

    store.beginTracking();
    const masked = store.mask(event.text);
    if (masked === event.text) return { action: "continue" };

    const changes = store.flushChanges();
    if (ctx.hasUI && changes.length > 0) {
      ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
    }

    return { action: "transform", text: masked };
  });

  // ---------------------------------------------------------------------------
  // tool_call — swap placeholders back to real values before tool executes
  // ---------------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    if (store.getStats().mappingCount === 0) return {};

    if (isToolCallEventType("bash", event)) {
      store.beginTracking();
      event.input.command = store.unmask(event.input.command);
      const changes = store.flushChanges();
      if (ctx.hasUI && changes.length > 0) {
        ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
      }
      return {};
    }

    if (isToolCallEventType("write", event)) {
      store.beginTracking();
      event.input.content = store.unmask(event.input.content);
      const changes = store.flushChanges();
      if (ctx.hasUI && changes.length > 0) {
        ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
      }
      return {};
    }

    if (isToolCallEventType("edit", event)) {
      store.beginTracking();
      if (Array.isArray(event.input.edits)) {
        for (const edit of event.input.edits) {
          edit.newText = store.unmask(edit.newText);
        }
      }
      const changes = store.flushChanges();
      if (ctx.hasUI && changes.length > 0) {
        ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
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

    const isReadResult = event.toolName === "read" || event.toolName === "bash";

    store.beginTracking();
    const newContent = transformTextBlocks(event.content, (text) => store.mask(text));

    if (newContent === event.content) return {};

    const changes = store.flushChanges();
    if (isReadResult && ctx.hasUI && changes.length > 0) {
      ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
    }

    return { content: newContent };
  });

  // ---------------------------------------------------------------------------
  // user_bash — intercept ! / !! command output before it enters context
  // ---------------------------------------------------------------------------
  pi.on("user_bash", async (event, ctx) => {
    const { createLocalBashOperations } = await import("@earendil-works/pi-coding-agent");
    const local = createLocalBashOperations();

    return {
      operations: {
        exec: async (command: string, cwd: string, options?: Record<string, unknown>) => {
          const result = await local.exec(command, cwd, options);
          // Only mask when output goes to LLM context (!, not !!)
          if (!event.excludeFromContext && result.output) {
            store.beginTracking();
            result.output = store.mask(result.output);
            const changes = store.flushChanges();
            if (ctx.hasUI && changes.length > 0) {
              ctx.ui.notify(changes.map(c => store.formatChange(c)).join("\n"), "info");
            }
          }
          return result;
        },
      },
    };
  });

  // ---------------------------------------------------------------------------
  // before_provider_request — silent last defense before payload leaves
  // ---------------------------------------------------------------------------
  pi.on("before_provider_request", (event, _ctx) => {
    try {
      const json = JSON.stringify(event.payload);
      const masked = store.mask(json);
      if (masked !== json && masked.length > 0) {
        return JSON.parse(masked);
      }
    } catch {
      // Never break the provider call
    }
  });

  // ---------------------------------------------------------------------------
  // context — silent full history scan before each LLM call
  // ---------------------------------------------------------------------------
  pi.on("context", async (event, _ctx) => {
    if (!event.messages || event.messages.length === 0) return;

    let changed = false;
    const messages = event.messages.map((msg: Record<string, unknown>) => {
      const transformed = transformMessageContent(msg, (text) => store.mask(text));
      if (transformed !== msg) changed = true;
      return transformed;
    });

    if (changed) return { messages };
  });

  // ---------------------------------------------------------------------------
  // /secret-mask command
  // ---------------------------------------------------------------------------
  pi.registerCommand("secret-mask", {
    description: "Show pi-secret-mask status and mapping table",
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
        // Display in a simple format
        const lines = mappings.map(
          (m) => `  ${m.real}  →  ${m.placeholder}`
        );
        ctx.ui.notify(`Secret mappings (${mappings.length}):\n${lines.join("\n")}`, "info");
        return;
      }

      // Default: status
      const stats = store.getStats();
      ctx.ui.notify(
        `pi-secret-mask\n` +
        `  Patterns: ${stats.patternCount}\n` +
        `  Active mappings: ${stats.mappingCount}`,
        "info"
      );
    },
  });
}
