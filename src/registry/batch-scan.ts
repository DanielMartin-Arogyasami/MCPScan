import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, createTarget } from "../scanner/engine.js";
import { connectToServer } from "../input/server-connector.js";
import type { ServerConfig, ScanResult, MCPToolDef } from "../types.js";
import { renderTerminal } from "../reporter/terminal.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface KnownServer {
  name: string;
  package: string;
  description: string;
  transport: string;
  command: string;
  args: string[];
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const live = args.includes("--live");
  const json = args.includes("--json");

  const serversPath = join(__dirname, "known-servers.json");
  const raw = readFileSync(serversPath, "utf-8");
  const knownServers: KnownServer[] = JSON.parse(raw);

  console.log(`\n  Batch scanning ${knownServers.length} known MCP servers...\n`);

  const results: ScanResult[] = [];

  for (const entry of knownServers) {
    const server: ServerConfig = {
      name: entry.name,
      transport: entry.transport as ServerConfig["transport"],
      command: entry.command,
      args: entry.args,
    };

    let tools: MCPToolDef[] = [
      {
        name: entry.package,
        description: entry.description,
        inputSchema: { type: "object" },
      },
    ];

    if (live) {
      try {
        console.log(`  Connecting to ${entry.name}...`);
        tools = await connectToServer(server);
        console.log(`  → ${tools.length} tools\n`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ✖ ${entry.name}: ${msg}\n`);
      }
    }

    const target = createTarget(server, tools);
    const result = scan(target);
    results.push(result);

    if (!json) {
      console.log(renderTerminal(result));
    }
  }

  if (json) {
    const summary = results.map((r) => ({
      server: r.server.name,
      score: r.score,
      grade: r.grade,
      findings: r.findings.length,
    }));
    console.log(JSON.stringify(summary, null, 2));
  }

  console.log(`\n  Scanned ${results.length} servers.`);
  const avg = Math.round(results.reduce((s, r) => s + r.score, 0) / results.length);
  console.log(`  Average score: ${avg}/100\n`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
