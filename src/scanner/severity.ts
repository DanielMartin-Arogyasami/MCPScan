import type { Severity, Finding } from "../types.js";

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

export function scoreFinding(severity: Severity): number {
  return SEVERITY_DEDUCTIONS[severity];
}

export function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const finding of findings) {
    score -= scoreFinding(finding.severity);
  }
  return Math.max(0, Math.min(100, score));
}

export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 40) return "D";
  return "F";
}
