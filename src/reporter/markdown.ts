import type { ScanResult, Severity } from "../types.js";

const SEVERITY_EMOJI: Record<Severity, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🔵",
  INFO: "ℹ️",
};

export function renderMarkdown(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`# MCPScan Report: ${result.server.name}`);
  lines.push("");
  lines.push(`**Score:** ${result.score}/100 (Grade: **${result.grade}**)`);
  lines.push(`**Transport:** ${result.server.transport}`);
  lines.push(`**Tools scanned:** ${result.tools.length}`);
  lines.push(`**Rules run:** ${result.rulesRun}`);
  lines.push(`**Scanned at:** ${result.scannedAt}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("> ✅ No security issues found!");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("## Findings");
  lines.push("");
  lines.push("| Severity | Rule ID | Rule | Tool | Message |");
  lines.push("|----------|---------|------|------|---------|");

  const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sorted = [...result.findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );

  for (const f of sorted) {
    const emoji = SEVERITY_EMOJI[f.severity];
    const tool = f.toolName ?? "-";
    const msg = f.message.replace(/\|/g, "\\|");
    lines.push(`| ${emoji} ${f.severity} | ${f.ruleId} | ${f.ruleName} | \`${tool}\` | ${msg} |`);
  }

  lines.push("");
  lines.push("## Summary");
  lines.push("");

  const summary: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of result.findings) summary[f.severity]++;

  for (const [sev, count] of Object.entries(summary)) {
    if (count > 0) {
      lines.push(`- ${SEVERITY_EMOJI[sev as Severity]} **${count}** ${sev}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}
