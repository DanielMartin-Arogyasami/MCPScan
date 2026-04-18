import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { execSync } from "node:child_process";
import { resolve } from "node:path";

const TARGETS_PATH = "data/top_500_targets.json";
const RESULTS_PATH = "data/empirical_study_results.json";
const TMP_DIR = "tmp_scans";
const DOCKER_IMAGE = "mcp-sandbox:latest";
const SCAN_TIMEOUT_MS = 120_000;

interface CrawlTarget {
  repoName: string;
  stars: number;
  cloneUrl: string;
  defaultBranch: string;
}

interface ScanOutput {
  repoName: string;
  stars: number;
  cloneUrl: string;
  defaultBranch: string;
  scanResult: unknown;
  scannedAt: string;
}

function sanitizeRepoName(repoName: string): string {
  return repoName.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function findConfigFile(repoDir: string): string | null {
  const candidates = [
    "mcp.json",
    "mcp.config.json",
    "mcp-config.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "config.json",
  ];

  for (const name of candidates) {
    if (existsSync(resolve(repoDir, name))) return name;
  }

  return null;
}

function main(): void {
  console.log("\n  MCPScan Sandbox Runner");
  console.log("  Batch-scanning targets in isolated Docker containers\n");

  if (!existsSync(TARGETS_PATH)) {
    console.error(`  Target list not found at ${TARGETS_PATH}`);
    console.error("  Run 'npm run research:crawl' first.\n");
    process.exit(1);
  }

  const raw = readFileSync(TARGETS_PATH, "utf-8");
  const targets: CrawlTarget[] = JSON.parse(raw);
  console.log(`  Loaded ${targets.length} targets\n`);

  mkdirSync(TMP_DIR, { recursive: true });

  const results: ScanOutput[] = [];
  let succeeded = 0;
  let failed = 0;

  for (const target of targets) {
    const safeName = sanitizeRepoName(target.repoName);
    const repoDir = resolve(TMP_DIR, safeName);
    const index = targets.indexOf(target) + 1;

    console.log(`  [${index}/${targets.length}] ${target.repoName} (${target.stars} stars)`);

    try {
      console.log(`    Cloning...`);
      execSync(
        `git clone --depth 1 "${target.cloneUrl}" "${repoDir}"`,
        { stdio: "pipe", timeout: 60_000 },
      );

      const configFile = findConfigFile(repoDir);
      const configArg = configFile ? `/target/${configFile}` : "--auto";

      console.log(`    Scanning (config: ${configFile ?? "auto-detect"})...`);

      const absoluteRepoDir = resolve(repoDir).replace(/\\/g, "/");
      const dockerCmd = [
        "docker run --rm",
        "--network none",
        `--memory=512m`,
        `--cpus=1`,
        `--pids-limit=256`,
        `-v "${absoluteRepoDir}:/target:ro"`,
        DOCKER_IMAGE,
        "--json",
        configArg,
      ].join(" ");

      let rawOutput = "";

      try {
        rawOutput = execSync(dockerCmd, {
          encoding: "utf-8",
          timeout: SCAN_TIMEOUT_MS,
          stdio: "pipe",
        });
      } catch (execError: unknown) {
        const err = execError as { stdout?: Buffer | string; stderr?: Buffer | string };
        rawOutput = err.stdout ? err.stdout.toString() : "";
        const stderr = err.stderr ? err.stderr.toString() : "";

        if (!rawOutput || rawOutput.trim() === "") {
          console.log(`    Skipping — scanner failed to run. (stderr: ${stderr.trim().split("\n")[0]})\n`);
          failed++;
          continue;
        }
      }

      try {
        const scanResult = JSON.parse(rawOutput);
        results.push({
          ...target,
          scanResult,
          scannedAt: new Date().toISOString(),
        });
        succeeded++;
        console.log(`    Done.\n`);
      } catch {
        console.log(`    Skipping — output was not valid JSON (possibly missing config).\n`);
        failed++;
      }
    } catch (err) {
      failed++;
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`    Error: ${msg.split("\n")[0]}\n`);
    } finally {
      if (existsSync(repoDir)) {
        try {
          rmSync(repoDir, { recursive: true, force: true });
        } catch {
          console.error(`    Warning: failed to clean up ${repoDir}`);
        }
      }
    }
  }

  mkdirSync("data", { recursive: true });
  writeFileSync(RESULTS_PATH, JSON.stringify(results, null, 2));

  console.log(`  ────────────────────────────────`);
  console.log(`  Scan complete.`);
  console.log(`    Succeeded: ${succeeded}`);
  console.log(`    Failed:    ${failed}`);
  console.log(`    Results:   ${RESULTS_PATH}`);
  console.log("");
}

main();
