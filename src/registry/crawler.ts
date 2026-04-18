import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const GITHUB_API = "https://api.github.com";
const TARGET_COUNT = 500;
const PER_PAGE = 100;
const OUTPUT_PATH = "data/top_500_targets.json";

interface GitHubSearchItem {
  full_name: string;
  stargazers_count: number;
  clone_url: string;
  default_branch: string;
}

interface GitHubSearchResponse {
  total_count: number;
  incomplete_results: boolean;
  items: GitHubSearchItem[];
}

interface CrawlTarget {
  repoName: string;
  stars: number;
  cloneUrl: string;
  defaultBranch: string;
}

function getToken(): string {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error("GITHUB_TOKEN environment variable is required");
  }
  return token;
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function handleRateLimit(response: Response): Promise<void> {
  const remaining = response.headers.get("x-ratelimit-remaining");
  const resetAt = response.headers.get("x-ratelimit-reset");

  if (remaining !== null && parseInt(remaining, 10) <= 1) {
    const resetTime = resetAt ? parseInt(resetAt, 10) * 1000 : Date.now() + 60_000;
    const waitMs = Math.max(0, resetTime - Date.now()) + 1000;
    console.log(`  Rate limit nearly exhausted. Pausing for ${Math.ceil(waitMs / 1000)}s...`);
    await sleep(waitMs);
  }
}

async function searchGitHub(query: string, page: number): Promise<GitHubSearchResponse> {
  const token = getToken();
  const url = `${GITHUB_API}/search/repositories?q=${encodeURIComponent(query)}&sort=stars&order=desc&per_page=${PER_PAGE}&page=${page}`;

  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  await handleRateLimit(response);

  if (response.status === 403 || response.status === 429) {
    console.log("  Rate limited. Waiting 60s before retry...");
    await sleep(60_000);
    return searchGitHub(query, page);
  }

  if (!response.ok) {
    throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<GitHubSearchResponse>;
}

async function crawl(): Promise<CrawlTarget[]> {
  const queries = [
    "topic:mcp-server",
    '"modelcontextprotocol/sdk"',
  ];

  const seen = new Set<string>();
  const results: CrawlTarget[] = [];

  for (const query of queries) {
    const maxPages = Math.ceil(TARGET_COUNT / PER_PAGE);

    for (let page = 1; page <= maxPages; page++) {
      if (results.length >= TARGET_COUNT) break;

      console.log(`  Fetching "${query}" page ${page}...`);
      const response = await searchGitHub(query, page);

      if (response.items.length === 0) break;

      for (const item of response.items) {
        if (seen.has(item.full_name)) continue;
        seen.add(item.full_name);

        results.push({
          repoName: item.full_name,
          stars: item.stargazers_count,
          cloneUrl: item.clone_url,
          defaultBranch: item.default_branch,
        });
      }

      await sleep(1500);
    }
  }

  results.sort((a, b) => b.stars - a.stars);
  return results.slice(0, TARGET_COUNT);
}

async function main(): Promise<void> {
  console.log("\n  MCPScan Research Crawler");
  console.log("  Discovering top 500 MCP servers on GitHub...\n");

  const targets = await crawl();

  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify(targets, null, 2));

  console.log(`\n  Saved ${targets.length} targets to ${OUTPUT_PATH}`);
  if (targets.length > 0) {
    console.log(`  Top result: ${targets[0].repoName} (${targets[0].stars} stars)`);
    console.log(`  Last result: ${targets[targets.length - 1].repoName} (${targets[targets.length - 1].stars} stars)`);
  }
  console.log("");
}

main().catch((err) => {
  console.error("Crawler failed:", err);
  process.exit(1);
});
