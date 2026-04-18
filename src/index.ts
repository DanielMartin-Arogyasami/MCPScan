// Core scanner
export { scan, createTarget, ALL_RULES } from "./scanner/engine.js";
export { calculateScore, scoreToGrade, scoreFinding } from "./scanner/severity.js";

// Rules
export { injectionRule } from "./scanner/rules/injection.js";
export { commandRule } from "./scanner/rules/command.js";
export { permissionsRule } from "./scanner/rules/permissions.js";
export { secretsRule } from "./scanner/rules/secrets.js";
export { exfiltrationRule } from "./scanner/rules/exfiltration.js";
export { shadowingRule } from "./scanner/rules/shadowing.js";
export { knownCvesRule } from "./scanner/rules/known-cves.js";

// Input
export { parseConfigFile, parseConfig, parseTestTools } from "./input/config-parser.js";
export { connectToServer } from "./input/server-connector.js";

// Reporters
export { renderTerminal } from "./reporter/terminal.js";
export { renderJSON } from "./reporter/json.js";
export { renderMarkdown } from "./reporter/markdown.js";
export { renderBadge, renderBadgeUrl, renderBadgeSvg } from "./reporter/badge.js";

// Types
export type {
  ServerConfig,
  MCPToolDef,
  ScanTarget,
  Finding,
  Severity,
  Rule,
  ScanResult,
  Transport,
} from "./types.js";
