import type { Rule, ScanTarget, ScanResult } from "../types.js";
import { calculateScore, scoreToGrade } from "./severity.js";
import { injectionRule } from "./rules/injection.js";
import { commandRule } from "./rules/command.js";
import { permissionsRule } from "./rules/permissions.js";
import { secretsRule } from "./rules/secrets.js";
import { exfiltrationRule } from "./rules/exfiltration.js";
import { shadowingRule } from "./rules/shadowing.js";
import { knownCvesRule } from "./rules/known-cves.js";

export const ALL_RULES: Rule[] = [
  injectionRule,
  commandRule,
  permissionsRule,
  secretsRule,
  exfiltrationRule,
  shadowingRule,
  knownCvesRule,
];

export function scan(target: ScanTarget): ScanResult {
  const start = Date.now();
  const findings = ALL_RULES.flatMap((rule) => rule.check(target));
  const score = calculateScore(findings);
  const grade = scoreToGrade(score);
  const elapsed = Date.now() - start;

  return {
    server: target.server,
    tools: target.tools,
    findings,
    score,
    grade,
    scannedAt: new Date().toISOString(),
    scanDurationMs: elapsed,
    rulesRun: ALL_RULES.length,
  };
}

export function createTarget(
  server: ScanTarget["server"],
  tools: ScanTarget["tools"] = [],
): ScanTarget {
  return { server, tools };
}
