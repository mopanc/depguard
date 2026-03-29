# depguard — Agent Skill Instructions

> Add this to your CLAUDE.md, .cursorrules, or agent instruction file to teach your AI coding agent how to use depguard.

---

## What is depguard?

depguard is an MCP server that provides real-time npm security auditing. It gives you 11 tools to check vulnerabilities, supply chain attacks, license compliance, maintenance health, and package quality — before installing any dependency.

## When to use depguard

**Always call depguard before:**
- Running `npm install <package>`
- Adding a dependency to package.json
- Recommending a package to the user
- Evaluating multiple package options

**Also use depguard when:**
- The user asks "should I use X?" or "what's a good library for Y?"
- Reviewing an existing project's dependencies
- The user asks about security or vulnerabilities in their project

## Available MCP Tools

### 1. `depguard_should_use` — Primary tool. Start here.

Call this when the user describes what they need (not a specific package).

**Input:** `{ "intent": "yaml parser" }`
**Returns:** Recommendation with one of four actions:
- `use-native` — Node.js has a built-in API. No package needed.
- `install` — Package scores well. Safe to install.
- `caution` — Package has risks. Review with user before installing.
- `write-from-scratch` — Better to implement the functionality yourself.

**Use when:** "I need an HTTP client", "I need to parse YAML", "I need UUID generation"

### 2. `depguard_audit` — Deep analysis of a specific package.

Call this when the user wants to install a specific named package.

**Input:** `{ "name": "express", "targetLicense": "MIT" }` or with a specific version: `{ "name": "express", "version": "4.17.1" }`
**Returns:** Full report with vulnerabilities, score, license compatibility, install script analysis, fix suggestions.

**Use when:** "Install express", "Is lodash safe?", "Audit this package", "Check express@4.17.1"

### 3. `depguard_score` — Quick quality check.

Call this when you need a fast score without full audit details.

**Input:** `{ "name": "axios", "targetLicense": "MIT" }`
**Returns:** Score 0-100 with breakdown (security, maintenance, popularity, license, dependencies).

**Use when:** Comparing multiple packages quickly, filtering search results.

### 4. `depguard_search` — Find packages by keywords.

Call this when looking for packages matching a description.

**Input:** `{ "keywords": "markdown parser", "limit": 5, "minScore": 60 }`
**Returns:** Ranked list of packages sorted by depguard quality score.

**Use when:** "Find me a good markdown library", "What options are there for X?"

### 5. `depguard_audit_project` — Audit entire package.json.

Call this to review all dependencies in a project at once. Scans direct deps (full audit), transitive deps from lock file (vulnerability check), and the `packageManager` field if present.

**Input:** `{ "path": "./package.json", "includeDevDependencies": true }`
**Returns:** Aggregate report with direct dep audits, transitive vulnerability summary (from lock file), packageManager audit, and overall severity counts.

**Use when:** "Audit my project", "Are my dependencies safe?", "Security review"

### 6. `depguard_audit_bulk` — Audit multiple specific packages.

Call this to audit a list of packages in parallel.

**Input:** `{ "packages": ["react", "express", "lodash"], "targetLicense": "MIT" }`
**Returns:** Same as audit_project but for a specific list.

**Use when:** Comparing a shortlist of candidates, auditing a subset of dependencies.

## Quick Decision Flow

| Situation | Tool to use |
|-----------|-------------|
| "I need X functionality" | `depguard_should_use` |
| "Install package Y" | `depguard_guard` |
| "Audit my project" | `depguard_audit_project` |
| "Compare A vs B vs C" | `depguard_audit_bulk` |
| "Deep dive on package Y" | `depguard_audit` |
| "Find a library for X" | `depguard_search` |
| "Clean up unused deps" | `depguard_sweep` |
| "Review my code" | `depguard_review` |

## Detailed Decision Flow

```
User needs functionality
        │
        ▼
  depguard_should_use(intent)
        │
        ├─ "use-native" → Show native API + example code. Do NOT install.
        ├─ "install" → Proceed with npm install.
        ├─ "caution" → Warn user. Show risks. Ask before installing.
        └─ "write-from-scratch" → Suggest implementing it. Explain why.

User names a specific package
        │
        ▼
  depguard_audit(package)
        │
        ├─ Score >= 60, no critical vulns → Safe to install.
        ├─ Score 40-59 or moderate vulns → Warn user. Suggest alternatives.
        ├─ Score < 40 or critical vulns → Do NOT install. Explain risks.
        └─ Suspicious install scripts → BLOCK. Alert user immediately.
```

## Score Interpretation

| Score | Action | What to tell the user |
|-------|--------|----------------------|
| >= 60 | **Install** | "This package scores well. Safe to install." |
| 40-59 | **Caution** | "This package has some concerns. Here are the risks: [list]. Want to proceed?" |
| < 40 | **Write your own** | "This package scores too low. I recommend implementing this yourself because [reasons]." |
| N/A | **Use native** | "Node.js has a built-in API for this: [api]. No package needed." |

## When to Block an Install

**Stop and alert the user if:**
- Package has **critical vulnerabilities** with no fix available
- Install script analysis returns `suspicious: true` with critical-severity risks
- Score is below the user's threshold (default: 60)
- License is incompatible with the project

**Example response when blocking:**
> "I checked this package with depguard and found critical security issues:
> - 1 critical vulnerability (Prototype Pollution) — no fix available
> - Suspicious install script detected: credential file access (~/.npmrc)
> - Score: 23/100
>
> I recommend not installing this package. Would you like me to find a safer alternative?"

## Token Savings

Every depguard response includes a `tokenSavings` field. Mention this when relevant:
- `responseTokens` — tokens in depguard's response
- `manualEstimate` — what equivalent manual research would cost
- `percentSaved` — percentage saved (typically 95-99%)

## Best Practices

1. **Always check `depguard_should_use` first** for new intents — it may recommend a native Node.js API
2. **Never skip the audit** for packages you haven't checked before
3. **Respect the score threshold** — don't install packages below it without user consent
4. **Mention native alternatives** when they exist — they reduce attack surface
5. **Use `depguard_audit_project`** when starting work on an existing project
6. **Report suspicious scripts immediately** — these are potential supply chain attacks

## Setup

```bash
# Claude Code
claude mcp add depguard -- npx -y depguard-cli --mcp

# Any MCP client (Claude Desktop, Cursor, Windsurf, Continue.dev, Cline, Roo Code)
# Add to your MCP config:
{
  "mcpServers": {
    "depguard": {
      "command": "npx",
      "args": ["-y", "depguard-cli", "--mcp"]
    }
  }
}
```

No API keys needed. No accounts. No configuration beyond the MCP setup.
