# Contributing to MCPScan

## Adding a New Detection Rule

1. Create `src/scanner/rules/my-rule.ts`:

```typescript
import type { Rule, ScanTarget, Finding } from "../../types.js";

export const myRule: Rule = {
  id: "MYRULE",
  name: "My Security Rule",
  description: "What this rule checks for",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;

    for (const tool of target.tools) {
      if (/* vulnerability detected */) {
        findings.push({
          ruleId: `MYRULE-${String(counter++).padStart(3, "0")}`,
          ruleName: "Specific Finding Name",
          severity: "HIGH",
          toolName: tool.name,
          message: "What was found",
          evidence: "The offending text",
          fix: "How to fix it",
        });
      }
    }

    return findings;
  },
};
```

2. Register in `src/scanner/engine.ts`:

```typescript
import { myRule } from "./rules/my-rule.js";

const ALL_RULES: Rule[] = [
  // ... existing rules
  myRule,
];
```

3. Export in `src/index.ts`:

```typescript
export { myRule } from "./scanner/rules/my-rule.js";
```

4. Add tests in `tests/scanner.test.ts`:

```typescript
describe("My Rule", () => {
  it("detects the vulnerability", () => { /* ... */ });
  it("does NOT false-positive on benign input", () => { /* ... */ });
});
```

## Severity Guidelines

| Level    | Score Deduction | When to Use                                    |
|----------|-----------------|------------------------------------------------|
| CRITICAL | -25             | RCE, data exfiltration, full system compromise |
| HIGH     | -15             | Significant risk, should fix before deployment |
| MEDIUM   | -8              | Potential risk, context-dependent              |
| LOW      | -3              | Minor concern, best practice                   |
| INFO     | 0               | Informational, no security impact              |

## Running Tests

```bash
npm test              # run all tests
npm run test:watch    # watch mode
npm run scan:test     # manual test against fixtures
```

## Code Style

- Every rule follows the same shape: import types, define patterns, export rule object with `check()` method, use a counter for unique finding IDs.
- Zero runtime dependencies — keep it that way.
- False positive reduction matters more than coverage.
