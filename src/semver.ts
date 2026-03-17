/**
 * Minimal semver range checker — zero dependencies.
 * Supports common version range patterns from GitHub advisories:
 *   "< 4.0.0", ">= 1.0.0, < 2.0.0", "<= 3.5.0", "= 1.2.3"
 *
 * Does NOT support: ||, ~, ^, *, x, pre-release tags, build metadata.
 * This is intentional — advisory ranges use simple comparators.
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

  // Split by comma for compound ranges: ">= 1.0.0, < 2.0.0"
  const parts = range.split(',').map(s => s.trim()).filter(Boolean)

  for (const part of parts) {
    const match = part.match(/^(>=|<=|>|<|=)\s*(.+)$/)
    if (!match) continue

    const op = match[1]
    const target = parse(match[2])
    if (!target) continue

    if (!matchComparator(ver, op, target)) {
      return false // One condition not met → not in vulnerable range
    }
  }

  return true
}
