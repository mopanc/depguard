/**
 * Known compromised packages database.
 *
 * Curated list of npm packages with documented security incidents:
 * supply chain attacks, account hijacks, maintainer sabotage, typosquats, protestware.
 *
 * Data stored in src/data/advisory-db.json, loaded once into Map on first access.
 * Lookups are O(1) via Map.get().
 *
 * Updated with each depguard release. Zero network calls.
 * Zero dependencies — only Node.js built-ins.
 */

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { matchesCompromisedRange } from './semver.js'

export type IncidentOrigin = 'curated' | 'ghsa' | 'osv'

export interface Incident {
  version: string
  type: 'supply-chain' | 'account-hijack' | 'maintainer-sabotage' | 'typosquat' | 'protestware'
  date: string
  cve: string | null
  description: string
  origin?: IncidentOrigin  // undefined treated as 'curated' for legacy entries
}

/** Entry in the exception list — package+identifier pair we explicitly trust. */
export interface AdvisoryException {
  package: string
  /** Either a GHSA id, CVE id, or "*" to suppress every incident for the package. */
  id: string
  reason: string
}

export interface CompromisedPackage {
  compromised: boolean
  severity: 'critical' | 'high' | 'low'
  incidents: Incident[]
}

interface AdvisoryDBData {
  version: string
  packages: Record<string, CompromisedPackage>
}

/** In-memory index — loaded once, O(1) lookups */
let db: Map<string, CompromisedPackage> | null = null
let dbVersion = ''
/** name → set of suppressed ids ("*" suppresses every incident) */
let exceptions: Map<string, Set<string>> = new Map()

/**
 * Load the advisory database from the bundled JSON file.
 * Called automatically on first lookup. Subsequent calls are no-ops.
 */
function ensureLoaded(): void {
  if (db) return

  db = new Map()
  exceptions = new Map()
  try {
    const thisDir = dirname(fileURLToPath(import.meta.url))
    const possibleDirs = [
      join(thisDir, 'data'),                          // dist/data/
      join(thisDir, '..', 'src', 'data'),             // src/data/ from dist/
      join(process.cwd(), 'src', 'data'),
      join(process.cwd(), 'dist', 'data'),
    ]

    for (const dataDir of possibleDirs) {
      try {
        const raw = readFileSync(join(dataDir, 'advisory-db.json'), 'utf-8')
        const data: AdvisoryDBData = JSON.parse(raw)
        dbVersion = data.version ?? 'unknown'
        for (const [name, pkg] of Object.entries(data.packages)) db.set(name, pkg)

        try {
          const excRaw = readFileSync(join(dataDir, 'advisory-db-exceptions.json'), 'utf-8')
          loadExceptions(JSON.parse(excRaw))
        } catch { /* exceptions file optional */ }
        return
      } catch { /* try next path */ }
    }

    // Final fallback: use createRequire which esbuild can statically resolve.
    try {
      const esmRequire = createRequire(import.meta.url)
      const data: AdvisoryDBData = esmRequire('../src/data/advisory-db.json')
      dbVersion = data.version ?? 'unknown'
      for (const [name, pkg] of Object.entries(data.packages)) db.set(name, pkg)
      try {
        const exc = esmRequire('../src/data/advisory-db-exceptions.json')
        loadExceptions(exc)
      } catch { /* optional */ }
    } catch { /* silently degrade — empty DB is safe */ }
  } catch { /* silently degrade — empty DB is safe */ }
}

function loadExceptions(parsed: unknown): void {
  if (!parsed || typeof parsed !== 'object') return
  const list = (parsed as { exceptions?: AdvisoryException[] }).exceptions
  if (!Array.isArray(list)) return
  for (const e of list) {
    if (!e?.package || !e?.id) continue
    const set = exceptions.get(e.package) ?? new Set<string>()
    set.add(e.id)
    exceptions.set(e.package, set)
  }
}

function isExcepted(name: string, incident: Incident): boolean {
  const set = exceptions.get(name)
  if (!set) return false
  if (set.has('*')) return true
  if (incident.cve && set.has(incident.cve)) return true
  return false
}

/**
 * Look up package-level incident history. Returns null if package is not in DB,
 * or if every incident for the package is excepted (no signal to act on).
 *
 * NOTE: this is name-based only — does NOT verify the user's installed version
 * matches an affected range. For scoring/guard/blocking decisions, use
 * `getCompromisedIncidents(name, version)` instead. See policy
 * `depguard-false-positive-aversion-policy`.
 */
export function lookupCompromised(name: string): CompromisedPackage | null {
  ensureLoaded()
  const pkg = db?.get(name)
  if (!pkg) return null
  const remaining = pkg.incidents.filter(i => !isExcepted(name, i))
  if (remaining.length === 0) return null
  if (remaining.length === pkg.incidents.length) return pkg
  return { ...pkg, incidents: remaining }
}

/**
 * Version-aware compromise check. Returns the list of incidents whose
 * `version` range INCLUDES the supplied version, after applying the exception
 * list. Empty array = package+version is not compromised.
 *
 * This is the FP-averse path. Use it from scorer, guard, daily-scan — anywhere
 * a decision (block / score=0 / alert) is made about a specific installed version.
 */
export function getCompromisedIncidents(name: string, version: string): Incident[] {
  ensureLoaded()
  const pkg = db?.get(name)
  if (!pkg || !version) return []
  return pkg.incidents.filter(i => {
    if (isExcepted(name, i)) return false
    return matchesCompromisedRange(version, i.version)
  })
}

/**
 * Check if a specific version of a package is known to be compromised.
 * Thin boolean wrapper over getCompromisedIncidents.
 */
export function isVersionCompromised(name: string, version: string): boolean {
  return getCompromisedIncidents(name, version).length > 0
}

/**
 * Get all incidents for a package (name-based, no version filter).
 * Excepted incidents are filtered out.
 */
export function getIncidents(name: string): Incident[] {
  ensureLoaded()
  const pkg = db?.get(name)
  if (!pkg) return []
  return pkg.incidents.filter(i => !isExcepted(name, i))
}

/**
 * Get the database version string.
 */
export function getDBVersion(): string {
  ensureLoaded()
  return dbVersion
}

/**
 * Get total number of packages in the database.
 */
export function getDBSize(): number {
  ensureLoaded()
  return db?.size ?? 0
}
