# Roadmap

The plan for depguard-cli — where we are and where we're going.

## Released

### v1.0.0 — Core Auditor
- [x] Full security audit (vulnerabilities, CVEs, advisories)
- [x] Package scoring (0-100) across 5 dimensions
- [x] npm search with quality ranking
- [x] Install vs write-from-scratch advisor
- [x] License compatibility checker (15+ SPDX identifiers)
- [x] MCP server (JSON-RPC 2.0 over stdio)
- [x] CLI tool
- [x] In-memory cache with TTL
- [x] 54 offline tests

### v1.1.0 — Token Savings
- [x] Token savings estimator in every MCP response
- [x] Manual step breakdown (what the alternative would cost)
- [x] Exported `calculateSavings()` and `TokenSavings` type

## Planned

### v1.2.0 — Smarter Analysis
- [ ] **Dependency tree audit** — recursively audit transitive dependencies, not just direct
- [ ] **Supply chain risk score** — detect typosquatting, suspicious maintainer changes, and new-package-with-high-downloads patterns
- [ ] **Bundle size estimation** — report install size and unpacked size to help decide if the package is worth the weight
- [ ] **Alternative suggestions** — when a package scores low, automatically suggest better alternatives

### v1.3.0 — Performance & Caching
- [ ] **Persistent cache** — file-based cache that survives process restarts (important for MCP servers that restart per session)
- [ ] **Parallel registry requests** — batch multiple package lookups into concurrent requests
- [ ] **Configurable cache TTL** — allow users to set cache duration via environment variable or config
- [ ] **Rate limit handling** — automatic backoff and retry on npm registry rate limits

### v1.4.0 — Ecosystem Expansion
- [ ] **PyPI support** — audit Python packages with the same scoring model
- [ ] **Cargo support** — audit Rust crates
- [ ] **Go modules support** — audit Go packages
- [ ] **Multi-ecosystem advisor** — `should_use` recommends across npm, PyPI, Cargo, and Go

### v1.5.0 — Project-Level Intelligence
- [ ] **Batch audit** — audit all dependencies in a `package.json` at once
- [ ] **Drift detection** — compare current dependency versions against latest and flag outdated/vulnerable ones
- [ ] **License report** — generate a full license compliance report for all project dependencies
- [ ] **CI integration** — GitHub Action that runs depguard on PRs that modify `package.json`

### Future Ideas
- [ ] **Vulnerability fix suggestions** — recommend specific version upgrades that resolve CVEs
- [ ] **Maintainer reputation** — score maintainers based on response time, release frequency, and multi-package track record
- [ ] **Custom scoring weights** — allow users to define their own scoring profiles via config file
- [ ] **Historical trends** — track how a package's score changes over time
- [ ] **API mode** — HTTP server for teams that want to run depguard as a shared service
- [ ] **npm publish** — publish to npm registry for easy global installation

## Contributing

Ideas and contributions are welcome. Open an issue to discuss before submitting a PR.
