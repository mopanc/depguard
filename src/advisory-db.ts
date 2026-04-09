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

export interface Incident {
  version: string
  type: 'supply-chain' | 'account-hijack' | 'maintainer-sabotage' | 'typosquat' | 'protestware'
  date: string
  cve: string | null
  description: string
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

/**
 * Load the advisory database from the bundled JSON file.
 * Called automatically on first lookup. Subsequent calls are no-ops.
 */
function ensureLoaded(): void {
  if (db) return

  db = new Map()
  try {
    // Resolve path relative to this module (works in dev, dist, and Netlify Functions)
    const thisDir = dirname(fileURLToPath(import.meta.url))
    const possiblePaths = [
      join(thisDir, 'data', 'advisory-db.json'),       // dist/data/
      join(thisDir, '..', 'src', 'data', 'advisory-db.json'), // from dist/ to src/
      join(process.cwd(), 'src', 'data', 'advisory-db.json'), // Netlify: cwd is repo root
      join(process.cwd(), 'dist', 'data', 'advisory-db.json'), // Netlify: from dist/
    ]

    for (const dbPath of possiblePaths) {
      try {
        const raw = readFileSync(dbPath, 'utf-8')
        const data: AdvisoryDBData = JSON.parse(raw)
        dbVersion = data.version ?? 'unknown'

        for (const [name, pkg] of Object.entries(data.packages)) {
          db.set(name, pkg)
        }
        return
      } catch { /* try next path */ }
    }

    // Final fallback: use createRequire which esbuild can statically resolve,
    // embedding the JSON directly in the bundle (works on Netlify Functions).
    try {
      const esmRequire = createRequire(import.meta.url)
      const data: AdvisoryDBData = esmRequire('../src/data/advisory-db.json')
      dbVersion = data.version ?? 'unknown'
      for (const [name, pkg] of Object.entries(data.packages)) {
        db.set(name, pkg)
      }
      return
    } catch { /* silently degrade — empty DB is safe */ }
  } catch { /* silently degrade — empty DB is safe */ }
}

/**
 * Check if a package has known security incidents.
 * Returns null if the package is not in the database (clean).
 */
export function lookupCompromised(name: string): CompromisedPackage | null {
  ensureLoaded()
  return db?.get(name) ?? null
}

/**
 * Check if a specific version of a package is known to be compromised.
 */
export function isVersionCompromised(name: string, version: string): boolean {
  const pkg = lookupCompromised(name)
  if (!pkg) return false

  return pkg.incidents.some(incident => {
    // Check if version matches any incident's affected versions
    const affectedVersions = incident.version.split(',').map(v => v.trim())
    return affectedVersions.some(av => {
      if (av.startsWith('>=')) return version >= av.slice(2)
      if (av === version) return true
      return false
    })
  })
}

/**
 * Get all incidents for a package.
 */
export function getIncidents(name: string): Incident[] {
  const pkg = lookupCompromised(name)
  return pkg?.incidents ?? []
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
