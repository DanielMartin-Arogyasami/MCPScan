import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseConfigFile, parseTestTools } from "../src/input/config-parser.js";
import { scan, createTarget } from "../src/scanner/engine.js";
import { renderTerminal } from "../src/reporter/terminal.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function runTestFile(name: string, filePath: string): void {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`  Testing: ${name}`);
  console.log(`${"=".repeat(60)}\n`);

  const servers = parseConfigFile(filePath);
  const testTools = parseTestTools(filePath);

  for (const server of servers) {
    const tools = testTools[server.name] ?? [
      {
        name: server.command ?? server.name,
        description: `MCP server: ${server.name}`,
        inputSchema: { type: "object" as const },
      },
    ];

    const target = createTarget(server, tools);
    const result = scan(target);
    console.log(renderTerminal(result));
  }
}

const vulnConfig = resolve(__dirname, "vulnerable-config.json");
const fullVuln = resolve(__dirname, "full-vuln-test.json");

runTestFile("Vulnerable Config (Secrets)", vulnConfig);
runTestFile("Full Vulnerability Test (All Rules)", fullVuln);
