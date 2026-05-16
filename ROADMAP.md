# Roadmap

The plan for depguard-cli — where we are, where we're going, and why.

## Released

### v1.0.0 — Core Auditor (2026-03-14)
- [x] Full security audit (vulnerabilities, CVEs, advisories)
- [x] Package scoring (0-100) across 5 dimensions
- [x] npm search with quality ranking
- [x] Install vs write-from-scratch advisor
- [x] License compatibility checker (15+ SPDX identifiers)
- [x] MCP server (JSON-RPC 2.0 over stdio)
- [x] CLI tool with JSON output
- [x] In-memory cache with TTL
- [x] 54 offline tests

### v1.1.0 — Token Savings (2026-03-15)
- [x] Token savings estimator in every MCP response
- [x] Manual step breakdown (what the alternative would cost)
- [x] Exported `calculateSavings()` and `TokenSavings` type

### v1.2.0 — Supply Chain Defense (2026-03-16)
- [x] GitHub Advisory Database integration (GHSA advisories)
- [x] Bulk audit (multiple packages at once)
- [x] Install script static analysis (9 attack pattern categories)
- [x] Persistent disk cache (~/.depguard/cache/, 24h TTL)

### v1.3.0 — Smart Advisor (2026-03-17)
- [x] GitHub token auth for higher rate limits (60 → 5,000 req/hr)
- [x] Project audit — audit entire package.json files
- [x] Vulnerability fix suggestions (specific version upgrades)
- [x] Smart native advisor (20+ Node.js built-in alternatives)
- [x] Semver range matching for accurate advisory filtering
- [x] 93 offline tests

### v1.4.0 — Guardian & Sweep (2026-03-21)
- [x] Pre-install guardian — verify + audit + allow/warn/block decision
- [x] AI hallucination guard — verify package existence on npm registry
- [x] Typosquatting detection — Levenshtein distance against 100+ popular packages
- [x] Dead dependency detection — scan project for unused packages in package.json
- [x] Config-aware sweep — recognizes eslint, prettier, typescript, jest, babel, tailwind, etc.
- [x] npm script binary detection — finds deps used via CLI in package.json scripts
- [x] @types/* pairing — recognizes type-only packages linked to runtime deps
- [x] 147 offline tests

### v1.5.0 — Deep Audit & Supply Chain Intelligence (2026-03-24)
- [x] Transitive dependency tree audit — BFS with concurrency, circular detection, depth limit
- [x] Phantom dependency detection — node_modules vs package.json comparison
- [x] Maintainer risk analysis — single-maintainer, free email, large team flags
- [x] Publication anomaly detection — burst publishing, dormant resurrection, version jumps
- [x] GitHub Action for CI/CD integration
- [x] 184 offline tests

### v1.6.0 — Static Code Analysis (2026-03-26)
- [x] Tarball download and source code scanning for malware patterns
- [x] Behavioral mismatch detection
- [x] 18+ code analysis patterns across 6 threat categories
- [x] 212 offline tests

### v1.7.0 — AI Code Review & Stats (2026-03-28)
- [x] AI Code Review (`depguard_review`) — console.logs, empty catch, broken imports, orphans, TODOs, empty tests
- [x] Quick mode (<500ms) and full mode (2-5s) with cross-file analysis
- [x] tsconfig path alias support for orphan detection
- [x] Local usage statistics (`depguard-cli stats`) — calls, tokens saved, threats blocked
- [x] MCP startup banner with session stats
- [x] MCP response condensing for large projects (80K char limit)
- [x] Improved tool descriptions guiding AI agents on when to call each tool
- [x] All scanner false positives eliminated (dynamic string construction)
- [x] 237 offline tests

### v1.8.0 — Architecture Redesign (2026-03-28)
- [x] Known compromised packages database — curated JSON with ~25 documented incidents (event-stream, colors, faker, etc.)
- [x] Comment stripping in code analysis — eliminates false positives from URLs in docs/comments
- [x] Code analysis informational (not punitive) — findings no longer reduce security score
- [x] Lock file parsing — package-lock.json and pnpm-lock.yaml for accurate phantom dep detection
- [x] Search score normalization — npm API scores capped at 0-100
- [x] Intl native alternatives — DateTimeFormat, RelativeTimeFormat, NumberFormat, Collator
- [x] Warnings deduplication in advisor results
- [x] 238 offline tests
- [x] 237 offline tests

### v1.11.0 — Remediation Planner (Phase 1a)
- [x] `depguard_remediate` MCP tool and `depguard-cli remediate` CLI command
- [x] `getDependencyParents` lockfile API tracks the parent chain for each transitive
- [x] `pulledInBy` field on `TransitiveVulnerability` reports
- [x] Output sorted by severity weight (critical × 100 + high × 10 + moderate + low × 0.1)
- [x] Action classifier infers fixes from `vulnerable_versions` upper bounds when `patched_versions` is absent (matches `npm audit fix`)
- [x] Read-only end-to-end. No filesystem writes, no npm invocation
- [x] 315 offline tests

---

## Phase 1.5 — Tier-up (in progress)

### Remediation roadmap (Eixo 2)
- [x] **Phase 1a** — group vulnerabilities by direct dep to bump (this release)
- [ ] **Phase 1b — constraint solver** — minimum set of direct-dep bumps that resolves max criticals; outputs Plan A (safe) / Plan B (medium) / Plan C (full) with breaking-change cost
- [ ] **Phase 2 — reachability analysis** — call-graph trace from project entry points to vulnerable functions; marks each vuln reachable / unreachable so 100 vulns becomes 7 actionable
- [ ] **Phase 3 — L2 codemod suggestions** — IA-translated migration patterns for known breaking changes; diff proposals only, never auto-applied

### Cryptographic provenance (Eixo 1)
- [ ] **Sigstore verification** — validate package signatures against the Sigstore transparency log
- [ ] **SLSA build provenance** — verify packages meet SLSA build provenance levels
- [ ] **npm provenance attestations** — verify packages use keyless signing (npm provenance)
- [ ] **GitHub attestations API** — end-to-end chain: source → CI → published artifact

---

## Phase 2 — Production Hardening (Q2 2026)

### v1.8.0 — CI/CD Integration
- [ ] **Exit codes** — configurable exit codes for CI pipelines (fail on critical, warn on moderate)
- [ ] **SARIF output** — GitHub Security tab compatible vulnerability format
- [ ] **PR comment bot** — auto-comment on PRs with audit summary and score changes
- [ ] **Diff mode** — only audit new/changed dependencies, not the entire lockfile

### v1.9.0 — Advanced Threat Detection
- [ ] **Typosquatting detection** — Levenshtein distance check against top 5000 npm packages
- [ ] **Maintainer change alerts** — flag packages where ownership recently transferred
- [ ] **Binary/native addon analysis** — flag packages that compile native code during install
- [ ] **Network behavior analysis** — detect install scripts that phone home

---

## Phase 3 — Ecosystem Expansion (Q3 2026)

### v2.0.0 — Multi-Ecosystem Support
- [ ] **PyPI support** — audit Python packages with the same scoring model
- [ ] **Cargo support** — audit Rust crates (aligns with OpenSSF Rust Foundation work)
- [ ] **Go modules support** — audit Go packages
- [ ] **Multi-ecosystem advisor** — `should-use` recommends across npm, PyPI, Cargo, and Go
- [ ] **Unified scoring model** — consistent 0-100 scoring across all ecosystems
- [ ] **Cross-ecosystem dependency mapping** — detect when npm packages wrap PyPI/Cargo packages

### v2.1.0 — Policy Engine
- [ ] **Custom policies** — define organization rules (e.g., "no GPL in production", "no packages < score 50")
- [ ] **Policy-as-code** — `.depguard.yml` config file for project-level policies
- [ ] **Compliance reports** — generate full license and security compliance documents
- [ ] **SBOM generation** — CycloneDX and SPDX format Software Bill of Materials
- [ ] **Policy inheritance** — organization policies cascade to all projects

---

## Phase 4 — Enterprise & Community (Q4 2026)

### v2.2.0 — Team Features
- [ ] **API server mode** — HTTP server for teams that want to run depguard as a shared service
- [ ] **Centralized cache** — shared cache across team members (Redis/S3 backend)
- [ ] **Audit history** — track how package scores change over time
- [ ] **Dashboard** — web UI for viewing project security posture
- [ ] **Webhook notifications** — alert when a dependency's score drops or new CVE is published

### v2.3.0 — Intelligence Layer
- [ ] **Maintainer reputation scoring** — response time, release frequency, multi-package track record
- [ ] **Community health signals** — GitHub stars trend, issue response time, bus factor
- [ ] **Alternative package suggestions** — when a package scores low, recommend better alternatives
- [ ] **Migration guides** — when suggesting alternatives, provide codemods or migration paths
- [ ] **Vulnerability prediction** — use historical patterns to flag likely-vulnerable packages

---

## AI Agent Surface — Skills & MCP marketplace audit (proposed)

Adjacent surface to npm: Claude Code Skills and MCP-server packages ship
third-party code that an AI agent installs and executes. Same trust model as
npm packages, same attack vectors (account hijack, prompt-injection via
manifest, env-var exfiltration, hidden subprocess), no equivalent audit tooling
yet. Suggested as a roadmap item by a depguard user pointing at Greg Pstrucha's
"Claude Code Skills Are a Massive Security Threat" talk (Sentry / Mastra, 2026).

Not date-committed — to be sequenced after the npm-side tier-up (broader scan,
runtime DB fetch) ships.

- [ ] **Skill SBOM (CycloneDX 1.6)** — extend the existing SBOM pipeline to
      consume skill bundles (`SKILL.md`, manifest, scripts, bundled binaries)
      and emit a CycloneDX component graph. Compliance hook for orgs running
      Claude Code under EU CRA / OMB M-22-18.
- [ ] **Skill advisory database** — mirror the npm `advisory-db.json` model
      with known-malicious skills (e.g., the ClawHavoc campaign), auto-refresh
      from a community feed.
- [ ] **`depguard skill-guard <skill-url>`** — pre-install guardian for skills.
      Static analysis of the manifest + bundled files; detect prompt-injection
      patterns, env-var access, subprocess execution; allow / warn / block
      decision mirroring the npm `guard` command.
- [ ] **MCP tool `depguard_audit_skill`** — expose the auditor as an MCP tool
      so a running agent can self-audit a skill *before* installing it, not
      after. Meta-defensive: the agent asks depguard to vet the skill it is
      about to absorb.

## Phase 5 — OpenSSF Alignment (2027)

### Strategic Goals
- [ ] **OpenSSF Scorecard integration** — incorporate OpenSSF Scorecard data into scoring
- [ ] **SLSA compliance checking** — verify packages meet SLSA build provenance levels
- [ ] **Sigstore verification** — validate package signatures against Sigstore transparency log
- [ ] **GUAC integration** — connect to Graph for Understanding Artifact Composition
- [ ] **OpenSSF Best Practices badge** — achieve passing/silver/gold badge for depguard itself
- [ ] **Trusted Publishing support** — verify packages use keyless signing (npm provenance)

### Community & Governance
- [ ] **OpenSSF working group participation** — Supply Chain Integrity, Vulnerability Disclosures
- [ ] **Alpha-Omega grant application** — apply for funding to embed security expertise
- [ ] **Public advisory database contributions** — contribute discovered patterns back to GHSA
- [ ] **Specification contributions** — help shape npm security standards
- [ ] **Academic partnerships** — collaborate on supply chain security research

---

## North Star Metrics

| Metric | Current | Q2 2026 Target | Q4 2026 Target |
|---|---|---|---|
| npm weekly downloads | — | 1,000 | 10,000 |
| GitHub stars | — | 100 | 1,000 |
| Packages in advisory DB | npm + GHSA | + PyPI + Cargo | + Go |
| Attack patterns detected | 9 + typosquatting | 15 | 25 |
| Test coverage | 134 tests | 200+ tests | 300+ tests |
| Ecosystems supported | npm | npm | npm, PyPI, Cargo, Go |
| MCP client integrations | 7 | 10 | 15 |
| OpenSSF Scorecard | — | Passing | Silver |

---

## How to Get Involved

### For Contributors
- Check [open issues](https://github.com/mopanc/depguard/issues) for `good first issue` labels
- Read [ARCHITECTURE.md](jm_docs/ARCHITECTURE.md) to understand the codebase
- All PRs require passing tests — `npm run check`

### For Organizations
- **Sponsor development** — fund specific roadmap items
- **Adopt and report** — use depguard in production and share feedback
- **Integrate** — build depguard into your security pipeline and share patterns

### For Security Researchers
- **Report attack patterns** — help us add new detection patterns
- **Advisory contributions** — flag packages that should be flagged
- **False positive reports** — help us improve accuracy

---

## Principles

1. **Zero dependencies** — the security tool must not be a supply chain risk itself
2. **Offline-first testing** — CI must never flake due to network
3. **AI-native** — MCP server is a first-class citizen, not an afterthought
4. **Transparent scoring** — every score must be reproducible and explainable
5. **Ecosystem-agnostic design** — the scoring model works across package registries
6. **Community-driven** — detection patterns improve through collective intelligence
