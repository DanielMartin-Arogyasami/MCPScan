# MCPScan

> Security scanner for MCP (Model Context Protocol) servers — like `npm audit` for AI agent tool integrations.

[![npm version](https://img.shields.io/npm/v/mcpscan)](https://www.npmjs.com/package/mcpscan)
[![license](https://img.shields.io/npm/l/mcpscan)](./LICENSE)

MCPScan detects **7 classes of vulnerabilities** in MCP server configurations and tool definitions:

| Code  | Category             | What it catches                                      |
|-------|----------------------|------------------------------------------------------|
| INJ   | Prompt Injection     | Hidden instructions in tool descriptions             |
| CMD   | Command Injection    | Shell/SQL injection risk in parameters               |
| PERM  | Excessive Permissions| Dangerous capability combos, wildcard access         |
| SEC   | Plaintext Secrets    | API keys, tokens, passwords in config/env vars       |
| EXFIL | Data Exfiltration    | Read+send tool chains that can leak data             |
| SHAD  | Tool Shadowing       | Name collisions, homograph attacks on tool names     |
| CVE   | Known CVEs           | Signatures of known MCP server vulnerabilities       |

## Quickstart

```bash
# Scan a config file
npx mcpscan ./claude_desktop_config.json

# Auto-detect installed MCP configs
npx mcpscan --auto

# Connect to live servers and scan real tool definitions
npx mcpscan --live ./config.json

# CI mode — JSON output + exit code 1 if score < 70
npx mcpscan --ci ./config.json
```

## Output Formats

```bash
npx mcpscan ./config.json              # Terminal (default) — color-coded box-drawing
npx mcpscan --json ./config.json       # JSON — machine-readable for pipelines
npx mcpscan --markdown ./config.json   # Markdown — tables for GitHub issues/PRs
npx mcpscan --badge ./config.json      # Badge — shields.io URL + SVG
```

## Library Usage

```typescript
import { scan, createTarget, parseConfigFile } from "mcpscan";

const servers = parseConfigFile("./config.json");

for (const server of servers) {
  const target = createTarget(server);
  const result = scan(target);

  console.log(`${result.server.name}: ${result.grade} (${result.score}/100)`);
  console.log(`  ${result.findings.length} findings`);
}
```

## GitHub Action

Add to `.github/workflows/mcp-security.yml`:

```yaml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mcpscan/mcpscan-action@v1
        with:
          config: ./mcp-config.json
          fail-below: 70
```

## Scoring

Score starts at **100** and deducts per finding:

| Severity | Deduction | Grade Thresholds |
|----------|-----------|------------------|
| CRITICAL | -25       | A: 90-100        |
| HIGH     | -15       | B: 80-89         |
| MEDIUM   | -8        | C: 65-79         |
| LOW      | -3        | D: 40-64         |
| INFO     | 0         | F: 0-39          |

## Development

```bash
npm install
npm test           # 44 tests
npx tsc --noEmit   # type check
npm run build      # build for npm
```

## License

MIT
