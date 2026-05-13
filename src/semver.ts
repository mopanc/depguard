/**
 * Minimal semver range checker — zero dependencies.
 * Supports common version range patterns from GitHub advisories:
 *   "< 4.0.0", ">= 1.0.0, < 2.0.0", "<= 3.5.0", "= 1.2.3"
 *   ">= 1.0.0, < 2.0.0 || >= 3.0.0, < 3.5.0" (OR clauses)
 *
 * Does NOT support: ~, ^, *, x, pre-release comparison, build metadata.
 * This is intentional — advisory ranges use simple comparators.
 * Unknown ranges are treated as vulnerable (safe default).
 */

interface SemVer {
  major: number
  minor: number
  patch: number
}

function parse(version: string): SemVer | null {
  // Strip leading 'v' and any pre-release/build suffix
  const clean = version.replace(/^v/, '').replace(/[-+].*$/, '').trim()
  const parts = clean.split('.')
  if (parts.length < 2) return null

  const major = parseInt(parts[0], 10)
  const minor = parseInt(parts[1], 10)
  const patch = parts.length >= 3 ? parseInt(parts[2], 10) : 0

  if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null
  return { major, minor, patch }
}

function compare(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major
  if (a.minor !== b.minor) return a.minor - b.minor
  return a.patch - b.patch
}

function matchComparator(version: SemVer, op: string, target: SemVer): boolean {
  const cmp = compare(version, target)
  switch (op) {
    case '<': return cmp < 0
    case '<=': return cmp <= 0
    case '>': return cmp > 0
    case '>=': return cmp >= 0
    case '=': return cmp === 0
    default: return cmp === 0
  }
}

/**
 * Strict, FP-averse range membership check — used for malware/compromised
 * package matching where false positives are worse than misses.
 *
 * Differences from satisfiesRange (which is recall-biased for CVE matching):
 *   - "all", "*", "", ">= 0" → matches any parseable version
 *   - exact-version list ("1.2.3,1.2.4") fully supported
 *   - unparseable input → returns false (FP-averse default)
 *
 * See policy `depguard-false-positive-aversion-policy`.
 */
export function matchesCompromisedRange(version: string, range: string): boolean {
  if (!version) return false
  const ver = parse(version)
  if (!ver) return false  // FP-averse: unparseable version → don't flag

  const r = (range ?? '').trim()
  if (r === '' || r === 'all' || r === '*' || r === '>= 0' || r === '>=0') {
    return true  // universal-match sentinels
  }

  // Special case: comma-separated list of exact versions with NO operators
  // (e.g., the curated "0.7.29,0.8.0,1.0.0" ua-parser-js incident format).
  // Treat each as a standalone exact-match OR clause.
  if (/^[\dv][\d.\-+a-zA-Z]*(?:\s*,\s*[\dv][\d.\-+a-zA-Z]*)+$/.test(r)) {
    const exacts = r.split(',').map(s => s.trim())
    return exacts.some(e => {
      const t = parse(e)
      return t !== null && compare(ver, t) === 0
    })
  }

  const orClauses = r.split('||').map(s => s.trim()).filter(Boolean)
  for (const clause of orClauses) {
    if (matchesCompromisedAndClause(ver, clause)) return true
  }
  return false
}

function matchesCompromisedAndClause(ver: SemVer, clause: string): boolean {
  const parts = clause.split(',').map(s => s.trim()).filter(Boolean)
  if (parts.length === 0) return false

  let usableComparators = 0
  for (const part of parts) {
    const m = part.match(/^(>=|<=|>|<|=)\s*(.+)$/)
    if (m) {
      const target = parse(m[2])
      if (!target) return false  // FP-averse: unparseable target → don't flag
      if (!matchComparator(ver, m[1], target)) return false
      usableComparators++
      continue
    }
    // No operator → treat as exact version match
    const target = parse(part)
    if (!target) return false  // FP-averse
    if (compare(ver, target) !== 0) return false
    usableComparators++
  }
  return usableComparators > 0  // FP-averse: empty clause → don't flag
}

/**
 * Check if a version satisfies a vulnerability range string.
 * Returns true if the version IS vulnerable (falls within the range).
 *
 * Examples:
 *   satisfiesRange("4.17.21", "< 4.17.20")  → false (not vulnerable)
 *   satisfiesRange("4.17.19", "< 4.17.20")  → true  (vulnerable)
 *   satisfiesRange("1.5.0", ">= 1.0.0, < 2.0.0") → true (vulnerable)
 */
export function satisfiesRange(version: string, range: string): boolean {
  const ver = parse(version)
  if (!ver) return true // If we can't parse, assume vulnerable (safe default)

  if (!range || range === '*') return true

  // Support OR clauses: "< 2.0.0 || >= 3.0.0, < 3.5.0"
  // Vulnerable if ANY OR clause matches
  const orClauses = range.split('||').map(s => s.trim()).filter(Boolean)

  for (const clause of orClauses) {
    if (satisfiesAndClause(ver, clause)) {
      return true // Vulnerable — matches at least one OR clause
    }
  }

  return false // Not vulnerable — doesn't match any OR clause
}

/**
 * Check if a version satisfies ALL conditions in an AND clause.
 * AND clauses are comma-separated: ">= 1.0.0, < 2.0.0"
 */
function satisfiesAndClause(ver: SemVer, clause: string): boolean {
  const parts = clause.split(',').map(s => s.trim()).filter(Boolean)
  let hadValidPart = false

  for (const part of parts) {
    const match = part.match(/^(>=|<=|>|<|=)\s*(.+)$/)
    if (!match) continue

    hadValidPart = true
    const op = match[1]
    const target = parse(match[2])
    if (!target) continue

    if (!matchComparator(ver, op, target)) {
      return false // One condition not met → not in this clause's range
    }
  }

  // If no valid parts were parsed, treat as vulnerable (safe default)
  return hadValidPart || true
}
