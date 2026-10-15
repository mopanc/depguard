/**
 * Exposure scan — answers "was this machine hit?" after a supply-chain incident.
 *
 * Where install-time tools (npm min-release-age, pnpm/yarn cooldowns, guard)
 * stop a bad version from coming in, this looks at what is ALREADY here:
 *
 *   1. every lock file under the given roots (all copies, nested included)
 *   2. globally installed packages (npm root -g)
 *   3. the npm download cache (~/.npm/_cacache) — proves a tarball was fetched
 *      on this machine even if the project that pulled it is gone
 *
 * Each (name, version) pair is checked with getCompromisedIncidents, the
 * version-aware, exception-aware path. A package is only reported when its
 * exact installed version falls inside a known-malicious range
 * (policy `depguard-false-positive-aversion-policy`).
 *
 * Zero dependencies — only Node.js built-ins.
 */

import { readdirSync, readFileSync, existsSync, realpathSync, statSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { homedir } from 'node:os'
import { execFileSync } from 'node:child_process'
import { parseLockfilePackages, LOCKFILE_NAMES } from './lockfile.js'
import { getCompromisedIncidents, getDBVersion, getDBSize } from './advisory-db.js'
import type { Incident } from './advisory-db.js'

export type ExposureLocationKind = 'lockfile' | 'global' | 'npm-cache'

export interface ExposureLocation {
  kind: ExposureLocationKind
  /** Lock file, global package directory, or cache index file */
  path: string
  /** npm lock files: install path inside the project (node_modules/a/node_modules/b) */
  installPath?: string
  /**
   * true  = this exact version is present in node_modules on disk
   * false = recorded in the lock file but not installed on disk
   * absent = could not tell (pnpm store, yarn PnP, nested non-npm copies)
   */
  onDisk?: boolean
  /** The lock file records that this version declares install scripts */
  hasInstallScript?: boolean
  /** npm-cache: when the tarball was downloaded (ISO 8601) */
  downloadedAt?: string
}

export interface ExposureFinding {
  name: string
  version: string
  incidents: Array<Pick<Incident, 'cve' | 'date' | 'description' | 'type'> & { origin: string }>
  locations: ExposureLocation[]
}

export interface ExposureReport {
  scannedAt: string
  dbVersion: string
  dbSize: number
  roots: string[]
  stats: {
    lockfiles: number
    globalPackages: number
    cacheEntries: number
    packagesChecked: number
    unreadableDirs: number
  }
  exposed: boolean
  findings: ExposureFinding[]
  nextSteps: string[]
  note: string
}

export interface ExposureOptions {
  /** Directories to search for lock files. Default: the user's home directory. */
  roots?: string[]
  /** Maximum directory depth below each root. Default 8. */
  maxDepth?: number
  /** Scan globally installed npm packages. Default true. */
  includeGlobal?: boolean
  /** Global node_modules directories. Default: `npm root -g`. */
  globalRoots?: string[]
  /** Scan the npm download cache. Default true. */
  includeCache?: boolean
  /** npm cache directory (the one containing _cacache). Default: $npm_config_cache or ~/.npm */
  cacheDir?: string
}

/**
 * Directories never descended into while looking for lock files: dependency
 * trees (lock files there belong to packages, not projects), VCS metadata,
 * caches, and OS folders that are large and never hold projects.
 */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn',
  '.npm', '.pnpm-store', '.yarn', '.cache', '.bun',
  '.cargo', '.rustup', '.gradle', '.m2', '.docker', '.Trash', '.nvm', '.volta',
  'Library', 'Applications', 'Pictures', 'Movies', 'Music',
  'AppData', 'Windows', 'Program Files', 'Program Files (x86)',
])

const DEFAULT_MAX_DEPTH = 8

export function scanExposure(options: ExposureOptions = {}): ExposureReport {
  const roots = (options.roots && options.roots.length > 0 ? options.roots : [homedir()]).map(r => resolve(r))
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH

  // name@version → locations
  const seen = new Map<string, { name: string; version: string; locations: ExposureLocation[] }>()
  const record = (name: string, version: string, location: ExposureLocation): void => {
    const key = `${name}@${version}`
    let entry = seen.get(key)
    if (!entry) {
      entry = { name, version, locations: [] }
      seen.set(key, entry)
    }
    entry.locations.push(location)
  }

  const stats = { lockfiles: 0, globalPackages: 0, cacheEntries: 0, packagesChecked: 0, unreadableDirs: 0 }

  // 1. Lock files
  for (const lockPath of findLockfiles(roots, maxDepth, stats)) {
    stats.lockfiles++
    const projectDir = dirname(lockPath)
    for (const pkg of parseLockfilePackages(lockPath)) {
      record(pkg.name, pkg.version, {
        kind: 'lockfile',
        path: lockPath,
        ...(pkg.path ? { installPath: pkg.path } : {}),
        ...onDiskState(projectDir, pkg.name, pkg.version, pkg.path),
        ...(pkg.hasInstallScript ? { hasInstallScript: true } : {}),
      })
    }
  }

  // 2. Global installs
  if (options.includeGlobal !== false) {
    for (const root of options.globalRoots ?? defaultGlobalRoots()) {
      for (const pkg of walkNodeModules(root)) {
        stats.globalPackages++
        record(pkg.name, pkg.version, { kind: 'global', path: pkg.dir, onDisk: true })
      }
    }
  }

  // 3. npm download cache
  if (options.includeCache !== false) {
    const cacheDir = options.cacheDir ?? defaultNpmCacheDir()
    for (const entry of readNpmCacheTarballs(cacheDir)) {
      stats.cacheEntries++
      record(entry.name, entry.version, {
        kind: 'npm-cache',
        path: entry.indexFile,
        ...(entry.downloadedAt ? { downloadedAt: entry.downloadedAt } : {}),
      })
    }
  }

  stats.packagesChecked = seen.size

  const findings: ExposureFinding[] = []
  for (const { name, version, locations } of seen.values()) {
    const incidents = getCompromisedIncidents(name, version)
    if (incidents.length === 0) continue
    findings.push({
      name,
      version,
      incidents: incidents.map(i => ({
        cve: i.cve,
        date: i.date,
        description: i.description,
        type: i.type,
        origin: i.origin ?? 'curated',
      })),
      locations,
    })
  }
  findings.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))

  const dbVersion = getDBVersion()
  return {
    scannedAt: new Date().toISOString(),
    dbVersion,
    dbSize: getDBSize(),
    roots,
    stats,
    exposed: findings.length > 0,
    findings,
    nextSteps: findings.length > 0 ? remediationSteps(findings) : [],
    note:
      `Matches exact installed versions against ${getDBSize()} known-malicious npm packages ` +
      `(advisory DB ${dbVersion}). A clean result means no KNOWN malicious version was found; ` +
      'it cannot detect malware that has not been reported yet. Yarn PnP zip caches are not scanned.',
  }
}

/** Find lock files under the roots, without following symlinks or entering dependency trees. */
function findLockfiles(roots: string[], maxDepth: number, stats: { unreadableDirs: number }): string[] {
  const found: string[] = []
  const visited = new Set<string>()
  const lockNames = new Set<string>(LOCKFILE_NAMES)

  const walk = (dir: string, depth: number): void => {
    let real: string
    try {
      real = realpathSync(dir)
    } catch {
      stats.unreadableDirs++
      return
    }
    if (visited.has(real)) return
    visited.add(real)

    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      stats.unreadableDirs++
      return
    }

    for (const e of entries) {
      if (e.isFile() && lockNames.has(e.name)) found.push(join(dir, e.name))
    }
    if (depth >= maxDepth) return
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink() || SKIP_DIRS.has(e.name)) continue
      walk(join(dir, e.name), depth + 1)
    }
  }

  for (const root of roots) {
    if (existsSync(root)) walk(root, 0)
  }
  return found.sort()
}

/** Read a package.json version, or null if absent or unreadable. */
function readPackageVersion(pkgDir: string): { name?: string; version?: string } | null {
  try {
    return JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf-8'))
  } catch {
    return null
  }
}

/**
 * Is this exact version present in the project's node_modules?
 * npm lock files give the exact install path; for other formats only the
 * hoisted top-level copy can be checked, and a mismatch there proves nothing.
 */
function onDiskState(projectDir: string, name: string, version: string, installPath?: string): { onDisk?: boolean } {
  if (installPath) {
    const pkg = readPackageVersion(join(projectDir, installPath))
    return { onDisk: pkg?.version === version }
  }
  const pkg = readPackageVersion(join(projectDir, 'node_modules', name))
  return pkg?.version === version ? { onDisk: true } : {}
}

function defaultGlobalRoots(): string[] {
  try {
    const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim()
    return root && existsSync(root) ? [root] : []
  } catch {
    return []
  }
}

/** Every package (name, version) in a node_modules tree, nested copies included. */
export function walkNodeModules(root: string): Array<{ name: string; version: string; dir: string }> {
  const out: Array<{ name: string; version: string; dir: string }> = []
  const visited = new Set<string>()

  const visitPackage = (dir: string, depth: number): void => {
    let real: string
    try {
      real = realpathSync(dir)
    } catch {
      return
    }
    if (visited.has(real) || depth > 32) return
    visited.add(real)
    const pkg = readPackageVersion(dir)
    if (pkg?.name && pkg.version) out.push({ name: pkg.name, version: pkg.version, dir })
    const nested = join(dir, 'node_modules')
    if (existsSync(nested)) visitTree(nested, depth + 1)
  }

  const visitTree = (nodeModules: string, depth: number): void => {
    let entries
    try {
      entries = readdirSync(nodeModules, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (e.name.startsWith('.')) continue
      const full = join(nodeModules, e.name)
      if (e.name.startsWith('@')) {
        let scoped
        try {
          scoped = readdirSync(full, { withFileTypes: true })
        } catch {
          continue
        }
        for (const s of scoped) visitPackage(join(full, s.name), depth)
      } else {
        visitPackage(full, depth)
      }
    }
  }

  if (existsSync(root)) visitTree(root, 0)
  return out
}

function defaultNpmCacheDir(): string {
  return process.env.npm_config_cache || join(homedir(), '.npm')
}

const TARBALL_KEY = /^make-fetch-happen:request-cache:(https?:\/\/[^\s]+\.tgz)$/

/**
 * Tarballs recorded in the npm cache index (cacache index-v5). Each index line
 * is "<hash>\t<json>" where json.key holds the tarball URL and json.time the
 * download time. Only registry-style tarball URLs are understood.
 */
export function readNpmCacheTarballs(cacheDir: string): Array<{ name: string; version: string; downloadedAt?: string; indexFile: string }> {
  const out: Array<{ name: string; version: string; downloadedAt?: string; indexFile: string }> = []
  const indexDir = join(cacheDir, '_cacache', 'index-v5')
  if (!existsSync(indexDir)) return out

  const files: string[] = []
  const collect = (dir: string, depth: number): void => {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const full = join(dir, e.name)
      if (e.isDirectory() && depth < 4) collect(full, depth + 1)
      else if (e.isFile()) files.push(full)
    }
  }
  collect(indexDir, 0)

  for (const file of files) {
    let raw: string
    try {
      if (statSync(file).size > 5_000_000) continue
      raw = readFileSync(file, 'utf-8')
    } catch {
      continue
    }
    for (const line of raw.split('\n')) {
      const tab = line.indexOf('\t')
      if (tab < 0) continue
      let entry: { key?: string; time?: number }
      try {
        entry = JSON.parse(line.slice(tab + 1))
      } catch {
        continue
      }
      const m = entry.key?.match(TARBALL_KEY)
      if (!m) continue
      const parsed = parseTarballUrl(m[1])
      if (!parsed) continue
      out.push({
        ...parsed,
        ...(typeof entry.time === 'number' ? { downloadedAt: new Date(entry.time).toISOString() } : {}),
        indexFile: file,
      })
    }
  }
  return out
}

/**
 * "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz" → { name: "@scope/pkg", version: "1.2.3" }
 * Also handles private registries mounted under a path prefix
 * ("https://host/api/npm/remote/debug/-/debug-4.4.2.tgz").
 * Returns null for anything that does not follow the registry layout.
 */
export function parseTarballUrl(url: string): { name: string; version: string } | null {
  let path: string
  try {
    path = decodeURIComponent(new URL(url).pathname)
  } catch {
    return null
  }
  const sep = path.lastIndexOf('/-/')
  if (sep < 0) return null
  const segments = path.slice(1, sep).split('/').filter(Boolean)
  if (segments.length === 0) return null
  const scoped = segments.length >= 2 && segments[segments.length - 2].startsWith('@')
  const name = scoped ? segments.slice(-2).join('/') : segments[segments.length - 1]
  const base = scoped ? segments[segments.length - 1] : name

  const file = path.slice(sep + 3)
  if (!file.startsWith(`${base}-`) || !file.endsWith('.tgz')) return null
  const version = file.slice(base.length + 1, -'.tgz'.length)
  if (!/^\d+\.\d+\.\d+/.test(version)) return null
  return { name, version }
}

function remediationSteps(findings: ExposureFinding[]): string[] {
  const ranHere = findings.some(f => f.locations.some(l => l.onDisk === true || l.kind === 'global' || l.kind === 'npm-cache'))
  const onDiskUnknown = findings.some(f => f.locations.some(l => l.kind === 'lockfile' && l.onDisk === undefined))

  const cleanup = [
    'In each affected project: upgrade or pin the package to a version outside the malicious range, delete node_modules, and reinstall with `npm ci --ignore-scripts` (or your package manager\'s equivalent); review before re-enabling scripts.',
    'If CI or another machine installed from these lock files, treat that environment as compromised and rotate its secrets.',
  ]

  if (!ranHere && !onDiskUnknown) {
    return [
      'The malicious version is recorded in lock files but was not found installed on disk, in global packages, or in the npm cache, so it does not appear to have run on this machine. Do not run an install until the lock files are fixed.',
      ...cleanup,
    ]
  }

  return [
    ranHere
      ? 'A malicious version was installed or downloaded on this machine. Treat the machine as compromised and do the credential steps from a different, clean device where possible.'
      : 'A malicious version is in lock files and could not be confirmed absent from disk (pnpm/yarn layouts). Assume it was installed and treat the machine as compromised.',
    'Rotate every credential reachable from this machine: npm tokens (`npm token list`, then revoke), GitHub tokens and SSH keys (`gh auth status`, GitHub Settings > Developer settings / SSH keys), cloud credentials (~/.aws, ~/.config/gcloud, ~/.azure), and secrets in .env files of the affected projects.',
    'Check your GitHub account for repositories, workflows, deploy keys or OAuth apps you did not create, and review recent npm publishes of packages you maintain.',
    ...cleanup,
    'Clear the npm cache so the malicious tarball cannot be reinstalled offline: `npm cache clean --force`.',
  ]
}
