import type { Rule, ScanTarget, Finding } from "../../types.js";

const SECRET_PATTERNS: { pattern: RegExp; name: string; severity: "CRITICAL" | "HIGH" }[] = [
  { pattern: /ghp_[A-Za-z0-9_]{36,}/, name: "GitHub Personal Access Token", severity: "CRITICAL" },
  { pattern: /github_pat_[A-Za-z0-9_]{22,}/, name: "GitHub Fine-Grained Token", severity: "CRITICAL" },
  { pattern: /gho_[A-Za-z0-9_]{36,}/, name: "GitHub OAuth Token", severity: "CRITICAL" },
  { pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{80,}/, name: "Anthropic API Key", severity: "CRITICAL" },
  { pattern: /sk-[A-Za-z0-9-]{40,}/, name: "OpenAI API Key", severity: "CRITICAL" },
  { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS Access Key ID", severity: "CRITICAL" },
  { pattern: /xoxb-[0-9]{10,}-[A-Za-z0-9-]+/, name: "Slack Bot Token", severity: "CRITICAL" },
  { pattern: /xoxp-[0-9]{10,}-[A-Za-z0-9-]+/, name: "Slack User Token", severity: "CRITICAL" },
  { pattern: /sq0atp-[A-Za-z0-9_-]{22,}/, name: "Square Access Token", severity: "HIGH" },
  { pattern: /key-[A-Za-z0-9]{32,}/, name: "Generic API Key", severity: "HIGH" },
];

const ENV_VAR_SECRET_NAMES = [
  /api[_-]?key/i,
  /api[_-]?secret/i,
  /access[_-]?token/i,
  /secret[_-]?key/i,
  /private[_-]?key/i,
  /password/i,
  /passwd/i,
  /auth[_-]?token/i,
  /bearer/i,
  /credential/i,
];

const SAFE_PLACEHOLDER_VALUES = [
  /^your[_-]/i,
  /^<.*>$/,
  /^\$\{/,
  /^env\./i,
  /^process\.env/i,
  /^TODO/i,
  /^CHANGE[_-]ME/i,
  /^xxx/i,
  /^placeholder/i,
];

function isSafePlaceholder(value: string): boolean {
  return SAFE_PLACEHOLDER_VALUES.some((p) => p.test(value));
}

export const secretsRule: Rule = {
  id: "SEC",
  name: "Plaintext Secrets Detection",
  description: "Detects API keys, tokens, and passwords in configuration and environment variables",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;
    const env = target.server.env ?? {};
    const allText = [
      ...Object.values(env),
      target.server.command ?? "",
      ...(target.server.args ?? []),
    ].join(" ");

    for (const { pattern, name, severity } of SECRET_PATTERNS) {
      const match = allText.match(pattern);
      if (match) {
        findings.push({
          ruleId: `SEC-${String(counter++).padStart(3, "0")}`,
          ruleName: name,
          severity,
          message: `Plaintext ${name} found in server configuration`,
          evidence: `${match[0].slice(0, 8)}${"*".repeat(Math.max(0, match[0].length - 8))}`,
          fix: "Use environment variable references instead of plaintext secrets",
        });
      }
    }

    for (const [key, value] of Object.entries(env)) {
      if (isSafePlaceholder(value)) continue;

      const isSensitiveName = ENV_VAR_SECRET_NAMES.some((p) => p.test(key));
      if (isSensitiveName && value.length > 8) {
        const alreadyFound = findings.some(
          (f) => f.evidence && value.includes(f.evidence.replace(/\*/g, "").trim()),
        );
        if (!alreadyFound) {
          findings.push({
            ruleId: `SEC-${String(counter++).padStart(3, "0")}`,
            ruleName: "Sensitive environment variable",
            severity: "HIGH",
            message: `Environment variable "${key}" appears to contain a plaintext secret`,
            evidence: `${key}=${value.slice(0, 4)}${"*".repeat(Math.max(0, value.length - 4))}`,
            fix: `Move "${key}" to a secure secrets manager or .env file (excluded from version control)`,
          });
        }
      }
    }

    for (const tool of target.tools) {
      const desc = tool.description ?? "";
      for (const { pattern, name, severity } of SECRET_PATTERNS) {
        const match = desc.match(pattern);
        if (match) {
          findings.push({
            ruleId: `SEC-${String(counter++).padStart(3, "0")}`,
            ruleName: `${name} in tool description`,
            severity,
            toolName: tool.name,
            message: `Plaintext ${name} found in tool "${tool.name}" description`,
            evidence: `${match[0].slice(0, 8)}${"*".repeat(Math.max(0, match[0].length - 8))}`,
            fix: "Remove secrets from tool descriptions",
          });
        }
      }
    }

    return findings;
  },
};
