import type { Rule, ScanTarget, Finding } from "../../types.js";

const PRIVILEGED_PATTERNS = [
  /\bsudo\b/i,
  /\badmin\b/i,
  /\broot\b/i,
  /\bsuperuser\b/i,
  /\bprivileged\b/i,
];

const WILDCARD_PATTERNS = [
  /\*\.\*/,
  /\ball\s+files\b/i,
  /\ball\s+directories\b/i,
  /\bunrestricted\b/i,
  /\bfull\s+access\b/i,
  /\bany\s+(file|path|directory|command)\b/i,
];

const FILE_READ_PATTERNS = [/read_file/i, /get_file/i, /list_dir/i, /file_read/i, /read_dir/i];
const FILE_WRITE_PATTERNS = [/write_file/i, /create_file/i, /delete_file/i, /file_write/i, /modify_file/i];
const NETWORK_PATTERNS = [/http_request/i, /fetch/i, /send_email/i, /upload/i, /download/i, /webhook/i, /api_call/i];
const EXEC_PATTERNS = [/exec/i, /run_command/i, /shell/i, /spawn/i, /execute/i];

function toolMatchesAny(name: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(name));
}

export const permissionsRule: Rule = {
  id: "PERM",
  name: "Excessive Permissions Detection",
  description: "Detects dangerous permission combinations and privilege escalation risks",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;
    const toolNames = target.tools.map((t) => t.name);

    for (const tool of target.tools) {
      const desc = tool.description ?? "";
      const text = `${tool.name} ${desc}`;

      for (const pattern of PRIVILEGED_PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            ruleId: `PERM-${String(counter++).padStart(3, "0")}`,
            ruleName: "Privileged access requested",
            severity: "CRITICAL",
            toolName: tool.name,
            message: `Tool "${tool.name}" requests privileged access`,
            evidence: match[0],
            fix: "Use least-privilege access — avoid sudo/admin/root unless absolutely required",
          });
          break;
        }
      }

      for (const pattern of WILDCARD_PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            ruleId: `PERM-${String(counter++).padStart(3, "0")}`,
            ruleName: "Wildcard permission",
            severity: "HIGH",
            toolName: tool.name,
            message: `Tool "${tool.name}" uses wildcard or unrestricted permissions`,
            evidence: match[0],
            fix: "Restrict access to specific files, directories, or resources",
          });
          break;
        }
      }
    }

    const hasFileRead = toolNames.some((n) => toolMatchesAny(n, FILE_READ_PATTERNS));
    const hasFileWrite = toolNames.some((n) => toolMatchesAny(n, FILE_WRITE_PATTERNS));
    const hasNetwork = toolNames.some((n) => toolMatchesAny(n, NETWORK_PATTERNS));
    const hasExec = toolNames.some((n) => toolMatchesAny(n, EXEC_PATTERNS));

    if (hasFileRead && hasFileWrite && hasNetwork) {
      findings.push({
        ruleId: `PERM-${String(counter++).padStart(3, "0")}`,
        ruleName: "Dangerous capability combination",
        severity: "HIGH",
        message: "Server has file read + file write + network access — can read, modify, and exfiltrate data",
        evidence: `Tools: ${toolNames.join(", ")}`,
        fix: "Separate capabilities into distinct servers with limited scope",
      });
    }

    if (hasExec && hasNetwork) {
      findings.push({
        ruleId: `PERM-${String(counter++).padStart(3, "0")}`,
        ruleName: "Execution + network combination",
        severity: "CRITICAL",
        message: "Server has command execution + network access — potential for remote code execution",
        evidence: `Tools: ${toolNames.join(", ")}`,
        fix: "Remove either execution or network capability from this server",
      });
    }

    if (hasExec && hasFileWrite) {
      findings.push({
        ruleId: `PERM-${String(counter++).padStart(3, "0")}`,
        ruleName: "Execution + file write combination",
        severity: "HIGH",
        message: "Server has command execution + file write — can create and execute arbitrary files",
        evidence: `Tools: ${toolNames.join(", ")}`,
        fix: "Restrict file write paths and command execution scope",
      });
    }

    return findings;
  },
};
