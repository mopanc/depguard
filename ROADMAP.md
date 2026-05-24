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

## Workspace Auto-Exec Surface — pre-open repo audit (proposed, priority)

A class of attack adjacent to supply-chain-via-package: **supply-chain-via-repo**.
Files committed to a repo can execute automatically the moment a developer opens
it in an IDE, runs `direnv allow`, or builds. No `npm install` required. No
"Trust Workspace" prompt — VS Code inherits workspace trust from parent folders
by default, and most devs trust their entire code directory.

This vector is the technical core of the rising "fake interview / take-home
test" social-engineering campaigns (publicly reported as *Contagious Interview*,
*DEV#POPPER*, and adjacent activity through 2024–2026): a recruiter — often
impersonating a real company on LinkedIn or a freelance platform — sends a
coding-test repo, the victim clones and opens it, and the payload exfiltrates
browser session tokens, SSH keys, password-manager state, cloud CLI tokens, and
crypto wallets before the IDE finishes loading. The same technique applies to
*"please review my PR"*, *"help me debug this OSS repo"*, or any pretext that
gets a target to clone-and-open.

Goal: a unified **pre-open audit** that runs between `git clone` and opening
the folder, enumerates every auto-execution surface in the repo, and classifies
each by risk. False-positive aversion is non-negotiable (see
`docs/policies/false-positive-aversion.md` if extracted, or the rule encoded in
the advisory-db work): a `tasks.json` with `runOn: folderOpen` running
`npm run watch` is INFO, not WARN. The output answers a single question:
*"if I open this repo right now, what runs without me clicking anything?"*

### Detector scope (single scan, exhaustive)
- [ ] **VS Code** — `.vscode/tasks.json` (`runOn: folderOpen`),
      `.vscode/settings.json` (`terminal.integrated.automationProfile.*`,
      `terminal.integrated.shellArgs.*`, `git.path`,
      `python.defaultInterpreterPath`, `eslint.nodePath`,
      `npm.packageManager` override), `.vscode/launch.json` (`preLaunchTask`,
      arbitrary `program` paths inside the repo),
      `.vscode/extensions.json` (recommended-extension surface)
- [ ] **Dev containers** — `.devcontainer/devcontainer.json`
      (`initializeCommand`, `onCreateCommand`, `postCreateCommand`,
      `postStartCommand`, `postAttachCommand`), referenced `Dockerfile` `RUN`
      lines, `features.*` that pull remote install scripts
- [ ] **JetBrains** — `.idea/runConfigurations/*.xml`, `.idea/workspace.xml`
      run configs, `.idea/externalDependencies.xml`, external-tool definitions
- [ ] **Cursor / Windsurf / Zed / Neovim / Helix** — IDE-specific equivalents:
      `.cursorrules` exec surface, `.zed/tasks.json`, `.nvim.lua` /
      `.exrc` / `.editorconfig` autoload paths the editor honours by default
- [ ] **Shell auto-eval** — `.envrc` (direnv — executes arbitrary shell on
      `cd`/folder open in many IDEs), `.tool-versions` + asdf/mise plugin
      hooks, `.python-version` + pyenv shims
- [ ] **Git surface in the cloned tree** — committed hooks (`.githooks/` +
      any tracked file that sets `core.hooksPath`), `.gitattributes` filter
      drivers (`filter.*.smudge`/`clean`) that invoke external commands on
      checkout, `.gitconfig` includes
- [ ] **Build systems** — `Makefile` default target invoked by IDE build
      shortcuts, `build.gradle(.kts)` init scripts and `apply from:` remote
      URLs, `pom.xml` profile auto-activation, `CMakeLists.txt`
      `execute_process` / `file(DOWNLOAD)`, `Justfile`, `Taskfile.yml`,
      `BUILD.bazel` `repository_rule` HTTP fetches, `meson.build` `run_command`
- [ ] **Package lifecycle** (already partially covered — link from unified
      report) — `package.json` `pre/postinstall`/`prepare`, `pyproject.toml`
      build backends + `setup.py`, `Cargo.toml` `build.rs`,
      `Gemfile` post-install hooks
- [ ] **MCP / AI agent configs** — `.mcp.json`, `.claude/settings.json`
      permissions and hooks, `.cursor/mcp.json`, agent-config files that
      pre-authorize tools or auto-start servers
- [ ] **Editor/runtime hidden paths** — `.vim/`, `.nvim/`,
      `.emacs.d/init.el`, `.ipython/profile_default/startup/` if cloned into
      a path the editor/runtime reads from

### Classification (FP-averse — precision > recall, always)
- **INFO** — auto-exec exists, command is legible and matches a known-benign
  pattern (`npm/cargo/tsc/ruff watch`, `prettier --check`, formatter daemons,
  language servers)
- **WARN** — shell pipe to remote (`curl … | sh`, `iwr … | iex`,
  `wget … | bash`), `eval`/`base64 -d`/`hex2bin` chains, write outside repo
  root, access patterns touching `~/.aws`, `~/.ssh`, `~/.config/gh`, browser
  profile paths, env-var exfil patterns, network-then-write sequences
- **HIGH** — obfuscation (long base64/hex blobs, multi-stage decode), explicit
  network-then-exec chain, IoC matches from the depguard advisory DB,
  cross-platform payload dispatch (Windows + macOS + Linux branches in a
  single auto-exec config — strong campaign signal)

### UX
- [ ] **`depguard scan`** — new *"Workspace auto-exec surface"* section in the
      standard report, even when no package issues are present
- [ ] **`depguard scan --workspace-only`** — fast pre-IDE check (sub-second
      target), exits non-zero on any HIGH
- [ ] **`depguard clone <url> [<dir>]`** — wrapper that runs `git clone`
      followed by `--workspace-only`; refuses to leave the working tree
      checked out (or quarantines it) on HIGH unless `--force`
- [ ] **Per-repo allowlist** — `.depguard-allow` to silence known-benign
      INFO/WARN entries (committed by maintainers, visible to reviewers; never
      auto-generated)
- [ ] **Hook recipe (opt-in, documented)** — `post-checkout` / `post-clone`
      integration so the scan fires automatically; the tool MUST NOT install
      this silently
- [ ] **MCP tool `depguard_workspace_audit`** — so an AI agent asked to "open
      and review this repo" runs the audit *before* the editor instance does

### Why this is escalated to priority
Fake-recruiter and fake-take-home-test campaigns delivering payloads via
cloneable repos are documented and growing through 2025–2026, with credible
reports from the developer community appearing weekly. The blast radius is the
developer's entire active session: browser cookies, password managers, SSH
keys, signing keys, cloud CLI tokens, crypto wallets, source-code access.
A pre-open scan is the only intervention point that doesn't require the
developer to already be skeptical — by the time the IDE shows the file tree,
the payload has already run.

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
