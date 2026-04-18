import type { Rule, ScanTarget, Finding } from "../../types.js";

const WELL_KNOWN_TOOLS = [
  "read_file",
  "write_file",
  "list_directory",
  "search_files",
  "execute_command",
  "run_terminal_command",
  "browser_navigate",
  "browser_click",
  "create_file",
  "edit_file",
  "delete_file",
  "read_resource",
  "list_resources",
  "get_weather",
  "send_email",
  "search_web",
  "run_python",
  "query_database",
  "http_request",
  "git_commit",
  "git_push",
];

const HOMOGLYPH_MAP: Record<string, string[]> = {
  a: ["\u0430"],         // Cyrillic а
  c: ["\u0441"],         // Cyrillic с
  e: ["\u0435"],         // Cyrillic е
  o: ["\u043E"],         // Cyrillic о
  p: ["\u0440"],         // Cyrillic р
  i: ["\u0456"],         // Cyrillic і
  l: ["\u04CF"],         // Cyrillic palochka
  "0": ["\u041E"],       // Cyrillic О
  "1": ["\u04CF"],       // Cyrillic palochka
};

function normalizeForComparison(name: string): string {
  let normalized = name.toLowerCase();
  for (const [canonical, glyphs] of Object.entries(HOMOGLYPH_MAP)) {
    for (const glyph of glyphs) {
      normalized = normalized.replaceAll(glyph.toLowerCase(), canonical);
    }
  }
  return normalized;
}

function hasHomoglyphs(name: string): boolean {
  for (const glyphs of Object.values(HOMOGLYPH_MAP)) {
    for (const glyph of glyphs) {
      if (name.includes(glyph)) return true;
    }
  }
  return false;
}

export const shadowingRule: Rule = {
  id: "SHAD",
  name: "Tool Shadowing Detection",
  description: "Detects tool name collisions with well-known tools and homograph attacks",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;
    const toolNames = target.tools.map((t) => t.name);

    for (const tool of target.tools) {
      if (WELL_KNOWN_TOOLS.includes(tool.name)) {
        findings.push({
          ruleId: `SHAD-${String(counter++).padStart(3, "0")}`,
          ruleName: "Well-known tool name collision",
          severity: "HIGH",
          toolName: tool.name,
          message: `Tool "${tool.name}" shadows a well-known MCP tool name`,
          evidence: tool.name,
          fix: "Use a unique, namespaced tool name (e.g., 'myapp_read_file' instead of 'read_file')",
        });
        continue;
      }

      const normalized = normalizeForComparison(tool.name);
      for (const knownTool of WELL_KNOWN_TOOLS) {
        if (normalized === normalizeForComparison(knownTool) && tool.name !== knownTool) {
          findings.push({
            ruleId: `SHAD-${String(counter++).padStart(3, "0")}`,
            ruleName: "Homograph tool name attack",
            severity: "CRITICAL",
            toolName: tool.name,
            message: `Tool "${tool.name}" is a homograph of well-known tool "${knownTool}"`,
            evidence: `"${tool.name}" visually mimics "${knownTool}"`,
            fix: "Rename tool to use only ASCII characters and avoid mimicking known tool names",
          });
          break;
        }
      }

      if (hasHomoglyphs(tool.name)) {
        const alreadyFlagged = findings.some((f) => f.toolName === tool.name);
        if (!alreadyFlagged) {
          findings.push({
            ruleId: `SHAD-${String(counter++).padStart(3, "0")}`,
            ruleName: "Suspicious Unicode in tool name",
            severity: "MEDIUM",
            toolName: tool.name,
            message: `Tool "${tool.name}" contains Unicode homoglyphs`,
            evidence: tool.name,
            fix: "Use only ASCII characters in tool names",
          });
        }
      }
    }

    const seen = new Map<string, string>();
    for (const name of toolNames) {
      const normalized = normalizeForComparison(name);
      const existing = seen.get(normalized);
      if (existing && existing !== name) {
        findings.push({
          ruleId: `SHAD-${String(counter++).padStart(3, "0")}`,
          ruleName: "Internal tool name collision",
          severity: "MEDIUM",
          message: `Tools "${existing}" and "${name}" have visually similar names`,
          evidence: `"${existing}" ≈ "${name}"`,
          fix: "Ensure all tool names are visually distinct",
        });
      }
      seen.set(normalized, name);
    }

    return findings;
  },
};
