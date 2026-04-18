import type { ScanResult } from "../types.js";

export function renderJSON(result: ScanResult): string {
  return JSON.stringify(
    {
      server: result.server.name,
      transport: result.server.transport,
      toolsScanned: result.tools.length,
      rulesRun: result.rulesRun,
      score: result.score,
      grade: result.grade,
      findings: result.findings.map((f) => ({
        ruleId: f.ruleId,
        ruleName: f.ruleName,
        severity: f.severity,
        message: f.message,
        toolName: f.toolName ?? null,
        evidence: f.evidence ?? null,
        fix: f.fix ?? null,
      })),
      summary: {
        critical: result.findings.filter((f) => f.severity === "CRITICAL").length,
        high: result.findings.filter((f) => f.severity === "HIGH").length,
        medium: result.findings.filter((f) => f.severity === "MEDIUM").length,
        low: result.findings.filter((f) => f.severity === "LOW").length,
        info: result.findings.filter((f) => f.severity === "INFO").length,
      },
      scannedAt: result.scannedAt,
      scanDurationMs: result.scanDurationMs,
    },
    null,
    2,
  );
}
