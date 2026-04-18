import { execSync } from "node:child_process";
import { scan, createTarget } from "../scanner/engine.js";
import { connectToServer } from "../input/server-connector.js";
import type { ServerConfig, ScanResult, MCPToolDef } from "../types.js";
import { renderTerminal } from "../reporter/terminal.js";

interface NpmPackage {
  name: string;
  description: string;
  version: string;
  keywords?: string[];
}

interface NpmSearchResult {
  objects: { package: NpmPackage }[];
}

function fetchNpmPackages(query: string, page: number, size: number = 20): NpmPackage[] {
  const from = page * size;
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=${size}&from=${from}`;

  try {
    const result = execSync(`curl -s "${url}"`, {
      encoding: "utf-8",
      timeout: 30000,
    });
    const parsed: NpmSearchResult = JSON.parse(result);
    return parsed.objects.map((o) => o.package);
  } catch {
    return [];
  }
}

function discoverMCPPackages(pages: number): NpmPackage[] {
  const queries = ["mcp-server", "model-context-protocol", "mcp server"];
  const seen = new Set<string>();
  const packages: NpmPackage[] = [];

  for (const query of queries) {
    for (let page = 0; page < pages; page++) {
      const results = fetchNpmPackages(query, page);
      if (results.length === 0) break;

      for (const pkg of results) {
        if (!seen.has(pkg.name)) {
          seen.add(pkg.name);
          packages.push(pkg);
        }
      }
    }
  }

  return packages;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const live = args.includes("--live");
  const json = args.includes("--json");
  const pagesIdx = args.indexOf("--pages");
  const pages = pagesIdx >= 0 ? parseInt(args[pagesIdx + 1] ?? "5", 10) : 5;

  console.log(`\n  Discovering MCP packages on npm (${pages} pages)...\n`);

  const packages = discoverMCPPackages(pages);
  console.log(`  Found ${packages.length} packages.\n`);

  if (dryRun) {
    for (const pkg of packages) {
      console.log(`  ${pkg.name}@${pkg.version}`);
      console.log(`    ${pkg.description ?? "(no description)"}\n`);
    }
    return;
  }

  const results: ScanResult[] = [];

  for (const pkg of packages) {
    const server: ServerConfig = {
      name: pkg.name,
      transport: "stdio",
      command: "npx",
      args: ["-y", pkg.name],
    };

    let tools: MCPToolDef[] = [
      {
        name: pkg.name,
        description: pkg.description ?? "",
        inputSchema: { type: "object" },
      },
    ];

    if (live) {
      try {
        console.log(`  Connecting to ${pkg.name}...`);
        tools = await connectToServer(server);
        console.log(`  → ${tools.length} tools\n`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ✖ ${pkg.name}: ${msg}\n`);
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

  console.log(`\n  Scanned ${results.length} packages.`);
  if (results.length > 0) {
    const avg = Math.round(results.reduce((s, r) => s + r.score, 0) / results.length);
    console.log(`  Average score: ${avg}/100\n`);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
