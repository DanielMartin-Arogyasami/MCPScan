import type { Rule, ScanTarget, Finding } from "../../types.js";

const DANGEROUS_PARAM_NAMES = [
  /^command$/i,
  /^cmd$/i,
  /^exec$/i,
  /^execute$/i,
  /^shell$/i,
  /^shell_command$/i,
  /^run$/i,
  /^script$/i,
  /^code$/i,
  /^eval$/i,
];

const SQL_PARAM_NAMES = [
  /^query$/i,
  /^sql$/i,
  /^sql_query$/i,
  /^statement$/i,
  /^raw_query$/i,
];

const DANGEROUS_DESCRIPTIONS = [
  /execut(e|es|ing)\s+(a\s+)?(shell|system|bash|cmd|command)/i,
  /run\s+(a\s+)?(shell|system|bash|cmd|command)/i,
  /\bspawn\s+(a\s+)?process/i,
  /\beval\(/i,
  /\bchild_process\b/i,
];

const SQL_DESCRIPTIONS = [
  /execut(e|es|ing)\s+(a\s+)?(raw\s+)?sql/i,
  /run\s+(a\s+)?(raw\s+)?sql/i,
  /\braw\s+query\b/i,
  /\bunsanitized\b/i,
];

export const commandRule: Rule = {
  id: "CMD",
  name: "Command Injection Detection",
  description: "Detects shell and SQL injection risk in tool parameters",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;

    for (const tool of target.tools) {
      const desc = tool.description ?? "";

      for (const pattern of DANGEROUS_DESCRIPTIONS) {
        const match = desc.match(pattern);
        if (match) {
          findings.push({
            ruleId: `CMD-${String(counter++).padStart(3, "0")}`,
            ruleName: "Shell command execution",
            severity: "CRITICAL",
            toolName: tool.name,
            message: `Tool "${tool.name}" description indicates shell command execution`,
            evidence: match[0],
            fix: "Use parameterized commands instead of raw shell execution",
          });
          break;
        }
      }

      for (const pattern of SQL_DESCRIPTIONS) {
        const match = desc.match(pattern);
        if (match) {
          findings.push({
            ruleId: `CMD-${String(counter++).padStart(3, "0")}`,
            ruleName: "Raw SQL execution",
            severity: "HIGH",
            toolName: tool.name,
            message: `Tool "${tool.name}" description indicates raw SQL execution`,
            evidence: match[0],
            fix: "Use parameterized queries instead of raw SQL",
          });
          break;
        }
      }

      if (!tool.inputSchema?.properties) continue;

      for (const [paramName, paramDef] of Object.entries(tool.inputSchema.properties)) {
        const paramDesc = paramDef.description ?? "";

        for (const pattern of DANGEROUS_PARAM_NAMES) {
          if (pattern.test(paramName)) {
            findings.push({
              ruleId: `CMD-${String(counter++).padStart(3, "0")}`,
              ruleName: "Dangerous parameter name",
              severity: "HIGH",
              toolName: tool.name,
              message: `Tool "${tool.name}" has parameter "${paramName}" suggesting command execution`,
              evidence: paramName,
              fix: "Rename parameter and ensure input is properly sanitized",
            });
            break;
          }
        }

        for (const pattern of SQL_PARAM_NAMES) {
          if (pattern.test(paramName)) {
            const isBenignQuery =
              /search|find|lookup|filter/i.test(paramDesc) ||
              /search|find|lookup|filter/i.test(tool.description ?? "");

            findings.push({
              ruleId: `CMD-${String(counter++).padStart(3, "0")}`,
              ruleName: "SQL parameter detected",
              severity: isBenignQuery ? "MEDIUM" : "HIGH",
              toolName: tool.name,
              message: `Tool "${tool.name}" has parameter "${paramName}" that may accept raw SQL`,
              evidence: paramName,
              fix: "Use parameterized queries and validate input",
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};
