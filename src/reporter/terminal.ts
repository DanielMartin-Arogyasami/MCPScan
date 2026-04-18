import type { ScanResult, Finding, Severity } from "../types.js";

const WIDTH = 72;

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";
const BG_RED = "\x1b[41m";
const BG_GREEN = "\x1b[42m";
const BG_YELLOW = "\x1b[43m";

const SEVERITY_STYLE: Record<Severity, { icon: string; color: string; bg?: string }> = {
  CRITICAL: { icon: "✖", color: RED, bg: BG_RED },
  HIGH: { icon: "▲", color: RED },
  MEDIUM: { icon: "●", color: YELLOW },
  LOW: { icon: "○", color: BLUE },
  INFO: { icon: "ℹ", color: CYAN },
};

function gradeColor(grade: string): string {
  if (grade === "A") return GREEN;
  if (grade === "B") return GREEN;
  if (grade === "C") return YELLOW;
  if (grade === "D") return RED;
  return RED;
}

function gradeBg(grade: string): string {
  if (grade === "A" || grade === "B") return BG_GREEN;
  if (grade === "C") return BG_YELLOW;
  return BG_RED;
}

function horizontal(left: string, fill: string, right: string): string {
  return left + fill.repeat(WIDTH - 2) + right;
}

function padLine(text: string, rawLen: number): string {
  const padding = WIDTH - 4 - rawLen;
  return `│ ${text}${" ".repeat(Math.max(0, padding))} │`;
}

function wrapText(text: string, maxWidth: number): string[] {
  const lines: string[] = [];
  const words = text.split(/\s+/);
  let current = "";

  for (const word of words) {
    if (current.length + word.length + 1 > maxWidth) {
      if (current) lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function emptyLine(): string {
  return `│${" ".repeat(WIDTH - 2)}│`;
}

function renderFinding(finding: Finding): string[] {
  const style = SEVERITY_STYLE[finding.severity];
  const lines: string[] = [];
  const innerWidth = WIDTH - 6;

  const header = `${style.color}${style.icon}${RESET} ${BOLD}[${finding.ruleId}]${RESET} ${finding.ruleName}`;
  const headerRaw = `${style.icon} [${finding.ruleId}] ${finding.ruleName}`;
  lines.push(padLine(header, headerRaw.length));

  const msgLines = wrapText(finding.message, innerWidth - 2);
  for (const ml of msgLines) {
    lines.push(padLine(`  ${DIM}${ml}${RESET}`, ml.length + 2));
  }

  if (finding.toolName) {
    const toolText = `Tool: ${finding.toolName}`;
    lines.push(padLine(`  ${MAGENTA}${toolText}${RESET}`, toolText.length + 2));
  }

  if (finding.evidence) {
    const evText = `Evidence: ${finding.evidence.slice(0, 50)}`;
    lines.push(padLine(`  ${DIM}${evText}${RESET}`, evText.length + 2));
  }

  if (finding.fix) {
    const fixLines = wrapText(`Fix: ${finding.fix}`, innerWidth - 2);
    for (const fl of fixLines) {
      lines.push(padLine(`  ${GREEN}${fl}${RESET}`, fl.length + 2));
    }
  }

  return lines;
}

export function renderTerminal(result: ScanResult): string {
  const lines: string[] = [];
  const gc = gradeColor(result.grade);
  const gb = gradeBg(result.grade);

  lines.push("");
  lines.push(horizontal("╭", "─", "╮"));
  lines.push(emptyLine());

  const title = "MCPScan Security Report";
  const titlePad = Math.floor((WIDTH - 2 - title.length) / 2);
  lines.push(`│${" ".repeat(titlePad)}${BOLD}${WHITE}${title}${RESET}${" ".repeat(WIDTH - 2 - titlePad - title.length)}│`);
  lines.push(emptyLine());

  lines.push(horizontal("├", "─", "┤"));
  lines.push(emptyLine());

  const serverText = `Server: ${result.server.name}`;
  lines.push(padLine(`${CYAN}${serverText}${RESET}`, serverText.length));

  const transportText = `Transport: ${result.server.transport}`;
  lines.push(padLine(`${DIM}${transportText}${RESET}`, transportText.length));

  const toolsText = `Tools scanned: ${result.tools.length}`;
  lines.push(padLine(`${DIM}${toolsText}${RESET}`, toolsText.length));

  const rulesText = `Rules run: ${result.rulesRun}`;
  lines.push(padLine(`${DIM}${rulesText}${RESET}`, rulesText.length));

  const timeText = `Duration: ${result.scanDurationMs}ms`;
  lines.push(padLine(`${DIM}${timeText}${RESET}`, timeText.length));

  lines.push(emptyLine());
  lines.push(horizontal("├", "─", "┤"));
  lines.push(emptyLine());

  const scoreLabel = `Score: ${result.score}/100`;
  const gradeLabel = ` ${result.grade} `;
  const scoreDisplay = `${gc}${BOLD}${scoreLabel}${RESET}  ${gb}${BOLD}${WHITE}${gradeLabel}${RESET}`;
  const scoreRawLen = scoreLabel.length + 2 + gradeLabel.length;
  lines.push(padLine(scoreDisplay, scoreRawLen));

  lines.push(emptyLine());

  if (result.findings.length === 0) {
    const noIssues = "No security issues found!";
    lines.push(padLine(`${GREEN}${BOLD}${noIssues}${RESET}`, noIssues.length));
    lines.push(emptyLine());
  } else {
    lines.push(horizontal("├", "─", "┤"));
    lines.push(emptyLine());

    const findingsHeader = `Findings (${result.findings.length})`;
    lines.push(padLine(`${BOLD}${findingsHeader}${RESET}`, findingsHeader.length));
    lines.push(emptyLine());

    const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const sorted = [...result.findings].sort(
      (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
    );

    for (const finding of sorted) {
      const fLines = renderFinding(finding);
      lines.push(...fLines);
      lines.push(emptyLine());
    }
  }

  const summary: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of result.findings) summary[f.severity]++;

  lines.push(horizontal("├", "─", "┤"));
  lines.push(emptyLine());

  const summaryParts = Object.entries(summary)
    .filter(([, count]) => count > 0)
    .map(([sev, count]) => {
      const style = SEVERITY_STYLE[sev as Severity];
      return `${style.color}${count} ${sev}${RESET}`;
    });
  const summaryRaw = Object.entries(summary)
    .filter(([, count]) => count > 0)
    .map(([sev, count]) => `${count} ${sev}`)
    .join("  ");

  if (summaryParts.length > 0) {
    lines.push(padLine(summaryParts.join("  "), summaryRaw.length));
  } else {
    const clean = "✓ Clean";
    lines.push(padLine(`${GREEN}${clean}${RESET}`, clean.length));
  }

  lines.push(emptyLine());
  lines.push(horizontal("╰", "─", "╯"));
  lines.push("");

  return lines.join("\n");
}
