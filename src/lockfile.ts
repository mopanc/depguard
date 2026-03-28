/**
 * Lock file parser — extracts all installed dependencies (direct + transitive).
 *
 * Supports package-lock.json (npm) and pnpm-lock.yaml (pnpm).
 * Used by sweep to distinguish true phantom deps from legitimate transitive deps.
 *
 * Zero dependencies — only Node.js built-ins.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Get all installed dependency names from the project's lock file.
 * Returns direct + transitive deps. Falls back to empty set if no lock file found.
 */
export function getAllInstalledDeps(projectPath: string): Set<string> {
  // Try npm first, then pnpm
  const npmLock = join(projectPath, 'package-lock.json')
  if (existsSync(npmLock)) {
    return parsePackageLock(npmLock)
  }

  const pnpmLock = join(projectPath, 'pnpm-lock.yaml')
  if (existsSync(pnpmLock)) {
    return parsePnpmLock(pnpmLock)
  }

  // No lock file — return empty (sweep will use node_modules scan as fallback)
  return new Set()
}

/**
 * Parse npm's package-lock.json (v2/v3 format).
 */
function parsePackageLock(lockPath: string): Set<string> {
  const deps = new Set<string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lock = JSON.parse(raw)

    // v2/v3 format uses "packages" with "node_modules/" prefixed keys
    if (lock.packages) {
      for (const key of Object.keys(lock.packages)) {
        if (!key || key === '') continue // root entry
        // key format: "node_modules/@scope/pkg" or "node_modules/pkg"
        const name = key.replace(/^node_modules\//, '')
        // Skip nested node_modules (e.g., "node_modules/a/node_modules/b")
        if (name.includes('node_modules/')) continue
        deps.add(name)
      }
    }

    // v1 fallback: uses "dependencies" object
    if (deps.size === 0 && lock.dependencies) {
      collectV1Deps(lock.dependencies, deps)
    }
  } catch { /* silently return empty set */ }

  return deps
}

/**
 * Recursively collect dependency names from v1 package-lock format.
 */
function collectV1Deps(
  depsObj: Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
  result: Set<string>,
): void {
  for (const [name, spec] of Object.entries(depsObj)) {
    result.add(name)
    if (spec.dependencies) {
      collectV1Deps(spec.dependencies as typeof depsObj, result)
    }
  }
}

/**
 * Parse pnpm's pnpm-lock.yaml (simple extraction, no YAML parser needed).
 */
function parsePnpmLock(lockPath: string): Set<string> {
  const deps = new Set<string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lines = raw.split('\n')

    // pnpm-lock.yaml v6+ uses "packages:" section with keys like "/pkg@version"
    let inPackages = false
    for (const line of lines) {
      if (line === 'packages:') {
        inPackages = true
        continue
      }
      if (inPackages && !line.startsWith(' ') && !line.startsWith('/') && line.trim() !== '') {
        inPackages = false
        continue
      }

      if (inPackages) {
        // Match package entries: "  /pkg@version:" or "  /@scope/pkg@version:"
        const match = line.match(/^\s+'?\/?(@[^@]+\/[^@]+|[^@/][^@]*)@/)
        if (match) {
          deps.add(match[1])
        }
      }
    }
  } catch { /* silently return empty set */ }

  return deps
}
