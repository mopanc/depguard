# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-03-17

### Added

- **GitHub auth token support** — set `GITHUB_TOKEN` env var to increase GitHub Advisory API rate limit from 60 to 5,000 requests/hour. Auto-detected if already configured (Closes #9)
- **Project audit** — new `depguard_audit_project` MCP tool that reads a `package.json` file path and audits all dependencies automatically, with optional devDependencies and auto-detected project license (Closes #11)
- **Vulnerability fix suggestions** — each advisory now includes a `fixSuggestions` field with the specific version to upgrade to (Closes #24)
- **Smart native advisor** — `should_use` now checks for native Node.js alternatives before recommending npm packages. Covers 20+ common intents (fetch, uuid, hashing, deep clone, testing, SQLite, etc.) with example code and minimum Node.js version (Closes #33)
- **Semver range matching** — `satisfiesRange()` for accurate version-based advisory filtering
- 9 new tests (93 total)

## [1.2.1] - 2026-03-17

### Fixed

- **Critical: Filter GitHub advisories by version** — previously reported historical advisories that were already patched in the current version, causing false positives. Now only reports vulnerabilities that actually affect the installed version.
- Added semver range checker for accurate version matching against advisory ranges

## [1.2.0] - 2026-03-16

### Added

- **GitHub Advisory Database** — audit now combines npm registry advisories with GitHub Security Advisories (GHSA) for broader vulnerability coverage
- **Bulk audit** — new `depguard_audit_bulk` MCP tool audits multiple packages in a single call, accepting a list of names or a `dependencies` object from `package.json`
- **Install script analysis** — static analysis of `preinstall`, `install`, and `postinstall` scripts for supply chain attack patterns (curl pipe sh, reverse shells, credential theft, obfuscated code, env var exfiltration)
- **Persistent disk cache** — results cached to `~/.depguard/cache/` with 24h TTL, surviving process restarts
- **Automatic cache cleanup** — expired cache entries removed on MCP server startup
- **GitHub rate limit protection** — gracefully degrades to npm-only when GitHub API rate limit is low
- **Advisory source tracking** — each advisory now includes a `source` field (`npm` or `github`)
- 10 new tests (74 total)

### Fixed

- **Binary name** — `npx -y depguard-cli --mcp` now works correctly (bin renamed from `depguard` to `depguard-cli`)
- Removed separate `depguard-mcp` binary — use `depguard-cli --mcp` instead

## [1.1.1] - 2026-03-16

### Added

- **`--mcp` flag on CLI** — `depguard-cli --mcp` launches the MCP server

### Changed

- **Renamed package** from `depguard.ai` to `depguard-cli` for clarity
- README: corrected MCP setup examples
- README: added `claude mcp add` CLI example for Claude Code users

## [1.1.0] - 2026-03-15

### Added

- **Token savings estimator** — every MCP tool response now includes a `tokenSavings` field showing:
  - `responseTokens` — tokens in the depguard response
  - `manualEstimate` — estimated tokens for the equivalent manual approach (WebSearch + WebFetch + reasoning)
  - `saved` — tokens saved
  - `percentSaved` — percentage reduction
  - `manualSteps` — breakdown of what the manual approach would involve
- New `tokens.ts` module with `calculateSavings()` and `estimateTokens()` functions
- Exported `TokenSavings` type and utility functions from the public API

## [1.0.0] - 2026-03-14

### Added

- Initial release
- `depguard_audit` — full security audit of npm packages (vulnerabilities, maintenance, license, dependencies, install scripts)
- `depguard_score` — score packages 0-100 across 5 dimensions (security, maintenance, popularity, license, dependencies)
- `depguard_search` — search npm for packages sorted by quality score
- `depguard_should_use` — recommend install vs write-from-scratch for a given intent
- MCP server (JSON-RPC 2.0 over stdio) — zero external dependencies
- CLI tool for terminal usage
- License compatibility checker supporting 15+ SPDX identifiers
- In-memory cache with TTL for registry requests
- Comprehensive test suite (54 tests)

[1.3.0]: https://github.com/mopanc/depguard/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/mopanc/depguard/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/mopanc/depguard/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/mopanc/depguard/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/mopanc/depguard/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mopanc/depguard/releases/tag/v1.0.0
