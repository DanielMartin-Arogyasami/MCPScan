import type { Rule, ScanTarget, Finding } from "../../types.js";

interface CVESignature {
  cve: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  matchServer?: RegExp;
  matchTool?: RegExp;
  matchDescription?: RegExp;
  fix: string;
}

const KNOWN_CVES: CVESignature[] = [
  {
    cve: "CVE-2024-MCP-001",
    description: "WhatsApp MCP server allows arbitrary file read via path traversal",
    severity: "CRITICAL",
    matchServer: /whatsapp/i,
    matchTool: /send_message|read_chat/i,
    matchDescription: /file|path|attachment/i,
    fix: "Update to latest version with path traversal fix",
  },
  {
    cve: "CVE-2024-MCP-002",
    description: "Filesystem MCP server exposes sensitive directories without sandboxing",
    severity: "HIGH",
    matchServer: /filesystem/i,
    matchTool: /read_file|list_directory/i,
    fix: "Configure allowed directories and enable sandbox mode",
  },
  {
    cve: "CVE-2024-MCP-003",
    description: "SQLite MCP server allows arbitrary SQL execution without parameterization",
    severity: "HIGH",
    matchServer: /sqlite|database/i,
    matchTool: /query|execute_sql|raw_query/i,
    fix: "Update to version with parameterized query enforcement",
  },
  {
    cve: "CVE-2024-MCP-004",
    description: "Git MCP server allows command injection via branch names",
    severity: "CRITICAL",
    matchServer: /\bgit\b/i,
    matchTool: /checkout|branch|commit/i,
    matchDescription: /branch|ref|name/i,
    fix: "Update and sanitize all branch/ref name inputs",
  },
  {
    cve: "CVE-2024-MCP-005",
    description: "Browser MCP server can be used for SSRF via URL parameter",
    severity: "HIGH",
    matchServer: /browser|puppeteer|playwright/i,
    matchTool: /navigate|goto|open_url|fetch_page/i,
    fix: "Add URL allowlist and block internal/private IP ranges",
  },
  {
    cve: "CVE-2024-MCP-006",
    description: "Slack MCP server leaks OAuth tokens in error messages",
    severity: "CRITICAL",
    matchServer: /slack/i,
    matchDescription: /token|oauth|xoxb|xoxp/i,
    fix: "Update to version with sanitized error messages",
  },
];

export const knownCvesRule: Rule = {
  id: "CVE",
  name: "Known CVE Detection",
  description: "Matches server configurations against a database of known MCP vulnerabilities",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;
    const serverName = target.server.name;
    const allDescriptions = target.tools.map((t) => t.description ?? "").join(" ");

    for (const cve of KNOWN_CVES) {
      let matches = true;

      if (cve.matchServer && !cve.matchServer.test(serverName)) {
        matches = false;
      }

      if (matches && cve.matchTool) {
        const hasMatchingTool = target.tools.some((t) => cve.matchTool!.test(t.name));
        if (!hasMatchingTool) matches = false;
      }

      if (matches && cve.matchDescription) {
        if (!cve.matchDescription.test(allDescriptions)) matches = false;
      }

      if (matches) {
        findings.push({
          ruleId: `CVE-${String(counter++).padStart(3, "0")}`,
          ruleName: cve.cve,
          severity: cve.severity,
          message: cve.description,
          evidence: `Server: ${serverName}, CVE: ${cve.cve}`,
          fix: cve.fix,
        });
      }
    }

    return findings;
  },
};
