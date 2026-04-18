import type { Rule, ScanTarget, Finding } from "../../types.js";

const INJECTION_PATTERNS: { pattern: RegExp; name: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" }[] = [
  {
    pattern: /<system>|<\/system>|<\|im_start\|>system/i,
    name: "System prompt tag in description",
    severity: "CRITICAL",
  },
  {
    pattern: /ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)/i,
    name: "Prompt override instruction",
    severity: "CRITICAL",
  },
  {
    pattern: /you\s+must\s+(always|never|not)\b/i,
    name: "Behavioral override directive",
    severity: "HIGH",
  },
  {
    pattern: /do\s+not\s+reveal|do\s+not\s+disclose|keep\s+secret|don['']t\s+tell/i,
    name: "Secrecy instruction",
    severity: "HIGH",
  },
  {
    pattern: /\bACT\s+AS\b|you\s+are\s+now\b|from\s+now\s+on\s+you/i,
    name: "Role hijacking instruction",
    severity: "HIGH",
  },
  {
    pattern: /<!--[\s\S]*?-->|%00|\\u0000/i,
    name: "Hidden content marker",
    severity: "MEDIUM",
  },
  {
    pattern: /\bbase64\s*[:=]\s*[A-Za-z0-9+/]{20,}/i,
    name: "Base64-encoded instruction",
    severity: "MEDIUM",
  },
  {
    pattern: /\[INST\]|\[\/INST\]|\bBEGIN\s+INSTRUCTION\b/i,
    name: "Instruction delimiter injection",
    severity: "CRITICAL",
  },
];

export const injectionRule: Rule = {
  id: "INJ",
  name: "Prompt Injection Detection",
  description: "Detects hidden instructions and prompt injection patterns in tool descriptions",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;

    for (const tool of target.tools) {
      const text = `${tool.name} ${tool.description ?? ""}`;

      const schemaDescriptions: string[] = [];
      if (tool.inputSchema?.properties) {
        for (const prop of Object.values(tool.inputSchema.properties)) {
          if (prop.description) schemaDescriptions.push(prop.description);
        }
      }
      const fullText = [text, ...schemaDescriptions].join(" ");

      for (const { pattern, name, severity } of INJECTION_PATTERNS) {
        const match = fullText.match(pattern);
        if (match) {
          findings.push({
            ruleId: `INJ-${String(counter++).padStart(3, "0")}`,
            ruleName: name,
            severity,
            toolName: tool.name,
            message: `Prompt injection detected in tool "${tool.name}": ${name}`,
            evidence: match[0],
            fix: "Remove or sanitize the suspicious instruction from the tool description",
          });
        }
      }
    }

    return findings;
  },
};
