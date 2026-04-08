/**
 * Lock file parser — extracts all installed dependencies (direct + transitive).
 *
 * Supports package-lock.json (npm), pnpm-lock.yaml (pnpm),
 * yarn.lock (yarn classic + berry), and bun.lock (bun).
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
  // Try npm first, then pnpm, yarn, bun
  const npmLock = join(projectPath, 'package-lock.json')
  if (existsSync(npmLock)) {
    return parsePackageLock(npmLock)
  }

  const pnpmLock = join(projectPath, 'pnpm-lock.yaml')
  if (existsSync(pnpmLock)) {
    return parsePnpmLock(pnpmLock)
  }

  const yarnLock = join(projectPath, 'yarn.lock')
  if (existsSync(yarnLock)) {
    return parseYarnLock(yarnLock)
  }

  const bunLock = join(projectPath, 'bun.lock')
  if (existsSync(bunLock)) {
    return parseBunLock(bunLock)
  }

  // No lock file — return empty (sweep will use node_modules scan as fallback)
  return new Set()
}

/**
 * Get all installed dependencies with their resolved versions from the lock file.
 * Returns Map<name, version> for direct + transitive deps.
 * Falls back to empty map if no lock file found.
 */
export function getAllInstalledVersions(projectPath: string): Map<string, string> {
  const npmLock = join(projectPath, 'package-lock.json')
  if (existsSync(npmLock)) {
    return parsePackageLockVersions(npmLock)
  }

  const pnpmLock = join(projectPath, 'pnpm-lock.yaml')
  if (existsSync(pnpmLock)) {
    return parsePnpmLockVersions(pnpmLock)
  }

  const yarnLock = join(projectPath, 'yarn.lock')
  if (existsSync(yarnLock)) {
    return parseYarnLockVersions(yarnLock)
  }

  const bunLock = join(projectPath, 'bun.lock')
  if (existsSync(bunLock)) {
    return parseBunLockVersions(bunLock)
  }

  return new Map()
}

/**
 * Parse npm's package-lock.json (v2/v3 format) — names + resolved versions.
 */
function parsePackageLockVersions(lockPath: string): Map<string, string> {
  const deps = new Map<string, string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lock = JSON.parse(raw)

    // v2/v3 format uses "packages" with "node_modules/" prefixed keys
    if (lock.packages) {
      for (const [key, entry] of Object.entries(lock.packages)) {
        if (!key || key === '') continue // root entry
        const name = key.replace(/^node_modules\//, '')
        if (name.includes('node_modules/')) continue // skip nested
        const version = (entry as { version?: string }).version
        if (version) deps.set(name, version)
      }
    }

    // v1 fallback
    if (deps.size === 0 && lock.dependencies) {
      collectV1DepsVersions(lock.dependencies, deps)
    }
  } catch { /* silently return empty map */ }

  return deps
}

/**
 * Recursively collect dependency name+version from v1 package-lock format.
 */
function collectV1DepsVersions(
  depsObj: Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
  result: Map<string, string>,
): void {
  for (const [name, spec] of Object.entries(depsObj)) {
    if (spec.version) result.set(name, spec.version)
    if (spec.dependencies) {
      collectV1DepsVersions(spec.dependencies as typeof depsObj, result)
    }
  }
}

/**
 * Parse pnpm's pnpm-lock.yaml — names + resolved versions.
 */
function parsePnpmLockVersions(lockPath: string): Map<string, string> {
  const deps = new Map<string, string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lines = raw.split('\n')

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
        const match = line.match(/^\s+'?\/?(@[^@]+\/[^@]+|[^@/][^@]*)@([^:]+):?/)
        if (match) {
          deps.set(match[1], match[2])
        }
      }
    }
  } catch { /* silently return empty map */ }

  return deps
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

/**
 * Parse yarn.lock (classic v1 + berry v2+).
 * Format: package entries like `pkg@^range:` followed by indented `version "x.y.z"`.
 * Works for both yarn classic and berry — the version line format is the same.
 */
function parseYarnLock(lockPath: string): Set<string> {
  const deps = new Set<string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lines = raw.split('\n')

    for (const line of lines) {
      // Skip comments and empty lines
      if (line.startsWith('#') || line.trim() === '') continue

      // Package entry lines are not indented and contain @ + colon
      // Examples: `express@^4.18.0:` or `"@babel/core@^7.0.0":` or `"@babel/core@^7.0.0", "@babel/core@^7.12.0":`
      if (!line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
        const name = extractYarnPackageName(line)
        if (name) deps.add(name)
      }
    }
  } catch { /* silently return empty set */ }

  return deps
}

/**
 * Parse yarn.lock — names + resolved versions.
 */
function parseYarnLockVersions(lockPath: string): Map<string, string> {
  const deps = new Map<string, string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lines = raw.split('\n')

    let currentName: string | null = null
    for (const line of lines) {
      if (line.startsWith('#') || line.trim() === '') continue

      if (!line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
        currentName = extractYarnPackageName(line)
      } else if (currentName) {
        const versionMatch = line.match(/^\s+version\s+"([^"]+)"/)
        if (versionMatch) {
          deps.set(currentName, versionMatch[1])
          currentName = null
        }
      }
    }
  } catch { /* silently return empty map */ }

  return deps
}

/**
 * Extract package name from a yarn.lock entry line.
 * Handles: `pkg@^1.0.0:`, `"@scope/pkg@^1.0.0":`, `"pkg@^1.0.0", "pkg@^2.0.0":`
 */
function extractYarnPackageName(line: string): string | null {
  // Remove trailing colon
  const entry = line.replace(/:$/, '').trim()

  // Take the first specifier (before any comma for multi-range entries)
  const first = entry.split(',')[0].trim()

  // Remove surrounding quotes
  const unquoted = first.replace(/^"/, '').replace(/"$/, '')

  // Extract name: everything before the last @version
  // For scoped: @scope/pkg@^1.0.0 → @scope/pkg
  // For regular: pkg@^1.0.0 → pkg
  const atIdx = unquoted.lastIndexOf('@')
  if (atIdx <= 0) return null // no @ or starts with @ but no version part

  const name = unquoted.substring(0, atIdx)
  return name || null
}

/**
 * Parse bun's bun.lock (JSONC format).
 * The packages object maps package names to arrays: ["name@version", ...].
 */
function parseBunLock(lockPath: string): Set<string> {
  const deps = new Set<string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lock = JSON.parse(stripJsoncComments(raw))

    if (lock.packages && typeof lock.packages === 'object') {
      for (const key of Object.keys(lock.packages)) {
        deps.add(key)
      }
    }
  } catch { /* silently return empty set */ }

  return deps
}

/**
 * Parse bun's bun.lock — names + resolved versions.
 * Package entries: `"name": ["name@version", ...]`
 */
function parseBunLockVersions(lockPath: string): Map<string, string> {
  const deps = new Map<string, string>()

  try {
    const raw = readFileSync(lockPath, 'utf-8')
    const lock = JSON.parse(stripJsoncComments(raw))

    if (lock.packages && typeof lock.packages === 'object') {
      for (const [key, value] of Object.entries(lock.packages)) {
        if (!Array.isArray(value) || value.length === 0) continue
        const spec = value[0] as string
        // spec format: "name@version" or "name@github:..." or "name@workspace:..."
        const version = extractBunVersion(spec)
        if (version) deps.set(key, version)
      }
    }
  } catch { /* silently return empty map */ }

  return deps
}

/**
 * Extract version from a bun.lock package spec like "express@4.21.1" or "@types/node@25.0.0".
 * Returns null for non-semver specs (workspace:, github:, etc).
 */
function extractBunVersion(spec: string): string | null {
  // For scoped packages (@scope/name@version), skip past the first @
  const searchFrom = spec.startsWith('@') ? spec.indexOf('/') : 0
  if (searchFrom < 0) return null

  const atIdx = spec.indexOf('@', searchFrom + 1)
  if (atIdx < 0) return null

  const version = spec.substring(atIdx + 1)
  // Skip non-semver specifiers (github:, workspace:, etc)
  if (version.includes(':')) return null
  return version || null
}

/**
 * Strip JSONC comments (// and /* ... *\/) for bun.lock parsing.
 * Bun.lock is JSONC (like tsconfig.json) — may contain trailing commas and comments.
 */
function stripJsoncComments(text: string): string {
  let result = ''
  let i = 0
  let inString = false

  while (i < text.length) {
    // Track string boundaries — count preceding backslashes to handle escaped quotes correctly.
    // `"\\"` is an escaped backslash followed by a real quote (even number of backslashes).
    // `"\\\"` is an escaped backslash + escaped quote (odd number).
    if (text[i] === '"') {
      let backslashes = 0
      let k = i - 1
      while (k >= 0 && text[k] === '\\') { backslashes++; k-- }
      if (backslashes % 2 === 0) {
        inString = !inString
      }
      result += text[i]
      i++
      continue
    }

    if (inString) {
      result += text[i]
      i++
      continue
    }

    // Line comment
    if (text[i] === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++
      continue
    }

    // Block comment
    if (text[i] === '/' && text[i + 1] === '*') {
      i += 2
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++
      if (i < text.length) i += 2
      continue
    }

    // Trailing commas before } or ] — skip them
    if (text[i] === ',') {
      let j = i + 1
      while (j < text.length && (text[j] === ' ' || text[j] === '\t' || text[j] === '\n' || text[j] === '\r')) j++
      if (j < text.length && (text[j] === '}' || text[j] === ']')) {
        i++
        continue
      }
    }

    result += text[i]
    i++
  }

  return result
}
