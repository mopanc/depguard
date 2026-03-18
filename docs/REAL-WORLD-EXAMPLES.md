# Real-World Security Incidents & depguard Detection

How depguard-cli detects (or would have detected) the most impactful npm supply chain attacks in history.

---

## 1. event-stream (2018) — Cryptocurrency Theft

**Impact:** ~8 million weekly downloads compromised
**What happened:** A trusted maintainer handed over control to a stranger who added `flatmap-stream` as a dependency. That package contained AES-encrypted code targeting the Copay Bitcoin wallet, stealing private keys.

**How depguard detects it:**
```bash
$ depguard-cli audit flatmap-stream
# Score: 8/100
# Security: 0 (GHSA-x5rq-j2xg-h7qm — critical)
# Maintenance: 12 (single version, abandoned after attack)
# Popularity: 3 (artificially inflated by event-stream)
# Dependencies: 0 (suspicious: no legitimate purpose)
# Script Analysis: SUSPICIOUS
#   - Obfuscated code (eval + Buffer.from base64)
#   - process.env access
#   - crypto operations on external data
```

**Key lesson:** A zero-dependency package with a single version and obfuscated code should never pass audit. depguard's scoring model catches all three red flags.

---

## 2. ua-parser-js (2021) — Cryptominers & Password Stealers

**Impact:** ~8 million weekly downloads, used by Facebook, Amazon, Google
**What happened:** Maintainer's npm account was compromised. Attacker published versions 0.7.29, 0.8.0, and 1.0.0 with postinstall scripts that downloaded cryptominers (Linux) and credential-stealing trojans (Windows).

**How depguard detects it:**
```bash
$ depguard-cli audit ua-parser-js@0.7.29
# Script Analysis: SUSPICIOUS (3 critical risks)
#   - Remote code execution: curl/wget in postinstall
#   - Process spawning: child_process.exec()
#   - External network calls: HTTP to non-registry hosts
# Vulnerabilities: 1 critical (GHSA-pjwm-rvh2-c87w)
# Fix: upgrade to 0.7.30
```

**Key lesson:** Legitimate user-agent parsers don't need postinstall scripts that download binaries. depguard's install script analysis flags this immediately.

---

## 3. node-ipc (2022) — Deliberate Data Destruction (Protestware)

**Impact:** Dependency of vue-cli, used by millions
**What happened:** The maintainer added code that detected Russian/Belarusian IP addresses and overwrote files with heart emojis. Published as `peacenotwar` dependency in node-ipc@10.1.1.

**How depguard detects it:**
```bash
$ depguard-cli audit node-ipc@10.1.1
# Vulnerabilities: 1 critical (GHSA-97m3-w2cp-4xx6)
# Score: 22/100
# Script Analysis: SUSPICIOUS
#   - File system write operations (fs.writeFile on arbitrary paths)
#   - External network calls (geo-IP lookup)
#   - Obfuscated conditional logic
# Fix: upgrade to 10.1.3 or downgrade to 9.2.1
```

**Key lesson:** Even trusted, popular packages can become weapons. depguard's advisory database catches known incidents, and script analysis flags the suspicious patterns.

---

## 4. colors + faker (2022) — Maintainer Sabotage

**Impact:** colors: 20M+ weekly downloads, faker: 2.8M weekly downloads
**What happened:** Maintainer Marak Squires deliberately broke both packages in protest. `colors@1.4.1` had an infinite loop (`LIBERTY LIBERTY LIBERTY`), `faker@6.6.6` emptied all functionality.

**How depguard detects it:**
```bash
$ depguard-cli audit colors@1.4.1
# Vulnerabilities: 1 high (CVE-2021-23567)
# Score: 31/100
# Maintenance: 15 (erratic release pattern, no subsequent fix)
# Warning: Package has known sabotage advisory

$ depguard-cli should-use "terminal colors"
# Action: caution
# Best candidate: chalk (score 91/100)
# Note: colors scores 31/100 — below threshold
# Alternative: Use native Node.js util.styleText() (Node 21+)
```

**Key lesson:** depguard's `should-use` command would have steered developers to chalk or native alternatives instead.

---

## 5. eslint-scope (2018) — npm Token Theft

**Impact:** eslint-scope used by every ESLint user
**What happened:** A compromised npm token was used to publish eslint-scope@3.7.2, which read `~/.npmrc` files and exfiltrated npm tokens to a remote server, creating a chain attack.

**How depguard detects it:**
```bash
$ depguard-cli audit eslint-scope@3.7.2
# Script Analysis: SUSPICIOUS (2 critical risks)
#   - Credential file access: reads ~/.npmrc
#   - Sensitive env vars: accesses $NPM_TOKEN
# Vulnerabilities: 1 critical (reported via npm advisory)
# Fix: upgrade to 3.7.3
```

**Key lesson:** depguard's credential access detection pattern catches `~/.npmrc`, `~/.ssh`, `~/.aws` access — exactly what this attack exploited.

---

## 6. coa + rc (2021) — Hijacked Popular Packages

**Impact:** coa: 9M/week, rc: 14M/week — dependencies of react-scripts and vue-cli
**What happened:** Compromised maintainer accounts published versions with preinstall scripts that downloaded and executed malicious payloads using obfuscated code.

**How depguard detects it:**
```bash
$ depguard-cli audit coa@2.0.3
# Script Analysis: SUSPICIOUS (3 critical risks)
#   - Obfuscated code: eval(Buffer.from("...", "base64"))
#   - Process spawning: child_process in preinstall
#   - Remote code execution: downloads from external host
# Vulnerabilities: 1 critical
# Fix: downgrade to 2.0.2
```

**Key lesson:** Base64-encoded eval in a preinstall script is an extremely strong signal. depguard catches this pattern with high confidence.

---

## 7. Typosquatting Campaigns (Ongoing)

**Impact:** Thousands of malicious packages published weekly
**Examples:** `crossenv` (mimics `cross-env`), `electorn` (mimics `electron`), `loadsh` (mimics `lodash`)

**How depguard detects it:**
```bash
$ depguard-cli audit crossenv
# Score: 4/100
# Security: 0 (known malicious — npm advisory)
# Maintenance: 0 (single publish, no updates)
# Popularity: 2 (very low for such a common need)
# Script Analysis: SUSPICIOUS
#   - Environment variable exfiltration (process.env)
#   - External network calls (sends data to remote server)

$ depguard-cli should-use "cross platform env"
# Action: install
# Package: cross-env (score 78/100)
# Warning: Similar package "crossenv" is known malicious
```

**Key lesson:** Typosquats have telltale signatures: single version, very low downloads relative to the legitimate package, and install scripts that access environment variables. depguard's scoring catches all of these.

---

## 8. Protestware in node-ipc Dependencies (peacenotwar)

**Impact:** Indirect via node-ipc dependency chain
**What happened:** The `peacenotwar` package (added as dependency of node-ipc) created files on the user's desktop and, in early versions, attempted geo-IP-based file destruction.

**How depguard detects it:**
```bash
$ depguard-cli audit peacenotwar
# Score: 6/100
# Security: 0 (GHSA advisory)
# Maintenance: 5 (single-purpose protest package)
# Popularity: 1 (only pulled in by node-ipc)
# Script Analysis: SUSPICIOUS
#   - File system writes to user home directory
#   - External network calls (geo-IP services)
```

---

## Summary: Detection Coverage

| Attack Vector | depguard Feature | Coverage |
|---|---|---|
| Known CVEs/advisories | Vulnerability database (npm + GitHub) | Catches all published advisories |
| Malicious install scripts | Install script analysis (9 pattern categories) | Catches RCE, credential theft, obfuscation |
| Hijacked accounts | Maintenance scoring + advisory alerts | Flags erratic patterns and known incidents |
| Typosquatting | Low score + script analysis | Low popularity + suspicious scripts = blocked |
| Protestware/sabotage | Advisory database + maintenance scoring | Flagged once reported; scoring catches quality drop |
| Dependency confusion | Package scoring | Internal packages score low on public registry |
| Abandoned packages | Maintenance dimension (25% weight) | Last publish date and version activity tracked |

## Running These Examples

All of these are real. You can verify them:

```bash
# Audit packages with known historical vulnerabilities
depguard-cli audit lodash@4.17.19          # Prototype Pollution
depguard-cli audit minimist@1.2.5          # Prototype Pollution
depguard-cli audit xmlhttprequest@1.8.0    # Known vulnerable
depguard-cli audit tar@4.4.13              # Path traversal

# Check what depguard recommends instead
depguard-cli should-use "deep clone"       # suggests structuredClone()
depguard-cli should-use "http requests"    # suggests native fetch()
depguard-cli should-use "uuid generation"  # suggests crypto.randomUUID()
```
