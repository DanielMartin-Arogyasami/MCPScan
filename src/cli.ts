#!/usr/bin/env node

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import { parseConfigFile, parseTestTools } from "./input/config-parser.js";
import { connectToServer } from "./input/server-connector.js";
import { scan, createTarget, ALL_RULES } from "./scanner/engine.js";
import { renderTerminal } from "./reporter/terminal.js";
import { renderJSON } from "./reporter/json.js";
import { renderMarkdown } from "./reporter/markdown.js";
import { renderBadge } from "./reporter/badge.js";
import type { MCPToolDef, ScanResult } from "./types.js";

const VERSION = "1.0.0";

const BOLD = "\x1b[1m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function printBanner(): void {
  console.log(`
${CYAN}${BOLD}  ╔══════════════════════════════════════╗
  ║          MCPScan v${VERSION}              ║
  ║   MCP Server Security Scanner        ║
  ╚══════════════════════════════════════╝${RESET}
${DIM}  Scanning for 7 vulnerability classes...${RESET}
`);
}

function printHelp(): void {
  console.log(`
${BOLD}Usage:${RESET}
  mcpscan <config-file>           Scan an MCP config file
  mcpscan --auto                  Auto-detect installed MCP configs

${BOLD}Options:${RESET}
  --auto                          Auto-detect Claude Desktop / Cursor configs
  --live                          Connect to live servers for real tool definitions
  --json                          Output JSON format
  --ci                            JSON output + exit code 1 if score < 70
  --markdown                      Output Markdown format
  --badge                         Output shields.io badge URL + SVG
  --list-rules                    Show all detection rules
  --threshold <n>                 Set CI fail threshold (default: 70)
  --help, -h                      Show this help
  --version, -v                   Show version
`);
}

function printRules(): void {
  console.log(`\n${BOLD}Detection Rules:${RESET}\n`);
  for (const rule of ALL_RULES) {
    console.log(`  ${CYAN}[${rule.id}]${RESET} ${BOLD}${rule.name}${RESET}`);
    console.log(`  ${DIM}${rule.description}${RESET}\n`);
  }
}

function autoDetectConfigs(): string[] {
  const home = homedir();
  const candidates = [
    join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    join(home, ".config", "claude", "claude_desktop_config.json"),
    join(home, ".cursor", "mcp.json"),
    join(home, "AppData", "Roaming", "Cursor", "User", "globalStorage", "mcp.json"),
    join(home, ".config", "cursor", "mcp.json"),
    "mcp.json",
    "mcp-config.json",
    ".mcp.json",
  ];

  return candidates.filter((p) => existsSync(p));
}

interface CliFlags {
  auto: boolean;
  live: boolean;
  json: boolean;
  ci: boolean;
  markdown: boolean;
  badge: boolean;
  listRules: boolean;
  help: boolean;
  version: boolean;
  threshold: number;
  configFile: string | null;
}

function parseArgs(args: string[]): CliFlags {
  const flags: CliFlags = {
    auto: false,
    live: false,
    json: false,
    ci: false,
    markdown: false,
    badge: false,
    listRules: false,
    help: false,
    version: false,
    threshold: 70,
    configFile: null,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--auto":
        flags.auto = true;
        break;
      case "--live":
        flags.live = true;
        break;
      case "--json":
        flags.json = true;
        break;
      case "--ci":
        flags.ci = true;
        flags.json = true;
        break;
      case "--markdown":
        flags.markdown = true;
        break;
      case "--badge":
        flags.badge = true;
        break;
      case "--list-rules":
        flags.listRules = true;
        break;
      case "--help":
      case "-h":
        flags.help = true;
        break;
      case "--version":
      case "-v":
        flags.version = true;
        break;
      case "--threshold":
        flags.threshold = parseInt(args[++i] ?? "70", 10);
        break;
      default:
        if (!arg.startsWith("-")) {
          flags.configFile = arg;
        }
        break;
    }
  }

  return flags;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const flags = parseArgs(args);

  if (flags.version) {
    console.log(`mcpscan v${VERSION}`);
    return;
  }

  if (flags.help) {
    printBanner();
    printHelp();
    return;
  }

  if (flags.listRules) {
    printBanner();
    printRules();
    return;
  }

  if (!flags.json) {
    printBanner();
  }

  let configFiles: string[] = [];

  if (flags.auto) {
    configFiles = autoDetectConfigs();
    if (configFiles.length === 0) {
      console.error("No MCP configs found. Specify a config file path or check your installation.");
      process.exit(1);
    }
    if (!flags.json) {
      console.log(`${DIM}  Found ${configFiles.length} config(s):${RESET}`);
      for (const f of configFiles) console.log(`  ${DIM}  → ${f}${RESET}`);
      console.log("");
    }
  } else if (flags.configFile) {
    const resolved = resolve(flags.configFile);
    if (!existsSync(resolved)) {
      console.error(`Config file not found: ${resolved}`);
      process.exit(1);
    }
    configFiles = [resolved];
  } else {
    printHelp();
    process.exit(1);
  }

  const results: ScanResult[] = [];
  let lowestScore = 100;

  for (const configPath of configFiles) {
    const servers = parseConfigFile(configPath);
    const testTools = parseTestTools(configPath);

    for (const server of servers) {
      let tools: MCPToolDef[] = [];

      if (flags.live) {
        if (!flags.json) {
          console.log(`  ${DIM}Connecting to ${server.name}...${RESET}`);
        }
        try {
          tools = await connectToServer(server);
          if (!flags.json) {
            console.log(`  ${DIM}  → ${tools.length} tools discovered${RESET}\n`);
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (!flags.json) {
            console.error(`  \x1b[31m✖ Failed to connect to ${server.name}: ${msg}${RESET}\n`);
          }
        }
      }

      if (tools.length === 0 && testTools[server.name]) {
        tools = testTools[server.name];
      }

      if (tools.length === 0) {
        tools = [
          {
            name: server.command ?? server.url ?? server.name,
            description: `MCP server: ${server.name}`,
            inputSchema: { type: "object" },
          },
        ];
      }

      const target = createTarget(server, tools);
      const result = scan(target);
      results.push(result);

      if (result.score < lowestScore) lowestScore = result.score;

      if (flags.json) {
        console.log(renderJSON(result));
      } else if (flags.markdown) {
        console.log(renderMarkdown(result));
      } else if (flags.badge) {
        const badge = renderBadge(result);
        console.log(`Badge URL: ${badge.url}\n`);
        console.log(badge.svg);
      } else {
        console.log(renderTerminal(result));
      }
    }
  }

  if (flags.ci && lowestScore < flags.threshold) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
