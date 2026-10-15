import { readFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { AuditReport, FetchFn, NpmAdvisory } from './types.js'
import { audit } from './audit.js'
import { getInstalledPackages, getDependencyParents } from './lockfile.js'
import type { InstalledPackage } from './lockfile.js'
import { fetchBulkAdvisories } from './registry.js'

/** Options for bulk audit */
export interface BulkAuditOptions {
  targetLicense?: string
  concurrency?: number
  fetcher?: FetchFn
  /** Exact version to audit per package name. Packages not listed are audited at their latest version. */
  versions?: Map<string, string>
}

/** Vulnerability entry for a transitive dependency */
export interface TransitiveVulnerability {
  name: string
  version: string
  advisories: NpmAdvisory[]
  /**
   * Direct deps (declared in package.json) that pull this transitive
   * into the install tree. Empty array means the parent chain could not
   * be resolved (older lockfile format, parse error, or the lockfile
   * format is not yet supported by getDependencyParents).
   */
  pulledInBy: string[]
}

/** Bulk audit result */
export interface BulkAuditReport {
  total: number
  clean: number
  vulnerable: number
  deprecated: number
  results: AuditReport[]
  summary: {
    critical: number
    high: number
    moderate: number
    low: number
  }
  /** Vulnerabilities found in transitive dependencies (from lock file) */
  transitiveSummary?: {
    totalDeps: number
    vulnerable: number
    critical: number
    high: number
    moderate: number
    low: number
    details: TransitiveVulnerability[]
  }
  /** Audit of the packageManager specified in package.json (e.g. yarn, pnpm) */
  packageManagerAudit?: AuditReport
  warnings?: string[]
}

/**
 * Audit multiple packages concurrently with controlled parallelism.
 * Defaults to 5 concurrent requests to stay within rate limits.
 */
export async function auditBulk(
  packages: string[],
  options: BulkAuditOptions = {},
): Promise<BulkAuditReport> {
  const {
    targetLicense = 'MIT',
    concurrency = 5,
    fetcher = globalThis.fetch,
    versions,
  } = options

  if (packages.length === 0) {
    return { total: 0, clean: 0, vulnerable: 0, deprecated: 0, results: [], summary: { critical: 0, high: 0, moderate: 0, low: 0 } }
  }

  const results: AuditReport[] = []

  // Process in batches to respect rate limits
  for (let i = 0; i < packages.length; i += concurrency) {
    const batch = packages.slice(i, i + concurrency)
    const batchResults = await Promise.all(
      batch.map(name => audit(name, targetLicense, fetcher, versions?.get(name))),
    )
    results.push(...batchResults)
  }

  const summary = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
  }

  let vulnerable = 0
  let deprecated = 0

  for (const r of results) {
    summary.critical += r.vulnerabilities.critical
    summary.high += r.vulnerabilities.high
    summary.moderate += r.vulnerabilities.moderate
    summary.low += r.vulnerabilities.low
    if (r.vulnerabilities.total > 0) vulnerable++
    if (r.deprecated) deprecated++
  }

  return {
    total: results.length,
    clean: results.length - vulnerable,
    vulnerable,
    deprecated,
    results,
    summary,
  }
}

/** Options for project audit */
export interface ProjectAuditOptions extends BulkAuditOptions {
  includeDevDependencies?: boolean
}

/**
 * Audit all dependencies from a package.json file.
 *
 * When a lock file is present (npm, pnpm, yarn or bun):
 * - Direct deps get a full audit (vulnerabilities, code analysis, scripts, license)
 *   at the version recorded in the lock file
 * - EVERY other installed copy (transitive, nested, duplicated at several
 *   versions) is checked for known vulnerabilities via the npm bulk advisory endpoint
 * - Results include both direct audit reports and a transitive vulnerability summary
 *
 * Without a lock file:
 * - Falls back to auditing direct deps only (with a warning)
 */
export async function auditProject(
  packageJsonPath: string,
  options: ProjectAuditOptions = {},
): Promise<BulkAuditReport> {
  const { includeDevDependencies = false, ...bulkOptions } = options
  const warnings: string[] = []

  const raw = readFileSync(packageJsonPath, 'utf-8')
  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
    license?: string
    packageManager?: string
  }

  const deps = Object.keys(pkg.dependencies ?? {})
  const devDeps = includeDevDependencies ? Object.keys(pkg.devDependencies ?? {}) : []
  const directPackages = [...new Set([...deps, ...devDeps])]

  // Use project license as target if not explicitly set
  if (!bulkOptions.targetLicense && pkg.license) {
    bulkOptions.targetLicense = pkg.license
  }

  // Audit packageManager if specified (e.g. "yarn@4.5.3", "pnpm@10.32.1")
  let packageManagerAudit: AuditReport | undefined
  if (pkg.packageManager) {
    const match = pkg.packageManager.match(/^(.+)@(.+)$/)
    if (match) {
      const [, pmName, pmVersion] = match
      const fetcher = bulkOptions.fetcher ?? globalThis.fetch
      packageManagerAudit = await audit(pmName, bulkOptions.targetLicense ?? 'MIT', fetcher, pmVersion)
      if (packageManagerAudit.vulnerabilities.total > 0) {
        warnings.push(
          `packageManager "${pkg.packageManager}" has ${packageManagerAudit.vulnerabilities.total} known vulnerability(ies). ` +
          `Consider updating to a patched version.`,
        )
      }
    }
  }

  // Read the lock file first: direct deps must be audited at the version that
  // is actually installed, not at the registry's latest.
  const projectDir = dirname(packageJsonPath)
  const installed = getInstalledPackages(projectDir)

  if (installed.length === 0) {
    warnings.push(
      'No lock file found (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock or bun.lock). ' +
      'Direct dependencies were audited at their latest published version, which may differ from what you would install, ' +
      'and transitive dependencies were not checked. Run your package manager\'s install to generate a lock file for full coverage.',
    )
    const directOnly = await auditBulk(directPackages, bulkOptions)
    return { ...directOnly, packageManagerAudit, warnings }
  }

  const directVersions = new Map<string, string>()
  const unresolved: string[] = []
  for (const name of directPackages) {
    const version = directInstalledVersion(name, installed)
    if (version) directVersions.set(name, version)
    else unresolved.push(name)
  }
  if (unresolved.length > 0) {
    warnings.push(
      `Could not determine the installed version of ${unresolved.join(', ')} from the lock file; ` +
      'audited the latest published version instead.',
    )
  }

  // Full audit on direct dependencies (code analysis, scripts, license, etc.)
  const directReport = await auditBulk(directPackages, { ...bulkOptions, versions: directVersions })

  // Every other installed copy is transitive, including nested copies of a
  // direct dependency's name at a different version.
  const transitiveVersions = new Map<string, Set<string>>()
  for (const p of installed) {
    if (directVersions.get(p.name) === p.version) continue
    const set = transitiveVersions.get(p.name) ?? new Set<string>()
    set.add(p.version)
    transitiveVersions.set(p.name, set)
  }

  // The bulk endpoint takes one version per name per request, so a package
  // installed at several versions is checked across several "layers". Each
  // advisory is then attributed to the exact version it was returned for.
  const layers: Map<string, string>[] = []
  for (const [name, versions] of transitiveVersions) {
    [...versions].forEach((version, i) => {
      if (!layers[i]) layers[i] = new Map()
      layers[i].set(name, version)
    })
  }

  const fetcher = bulkOptions.fetcher ?? globalThis.fetch
  const transitiveFindings: Array<{ name: string; version: string; advisories: NpmAdvisory[] }> = []
  for (const layer of layers) {
    const advisories = await fetchBulkAdvisories(layer, fetcher)
    for (const [name, list] of advisories) {
      transitiveFindings.push({ name, version: layer.get(name) ?? 'unknown', advisories: list })
    }
  }
  const totalTransitive = [...transitiveVersions.values()].reduce((n, set) => n + set.size, 0)

  // Resolve which direct dep(s) pull each transitive in. Empty if the
  // lockfile format isn't supported yet or the file is malformed.
  const parentMap = getDependencyParents(projectDir)

  // Build transitive summary
  const transitiveDetails: TransitiveVulnerability[] = []
  let tCritical = 0, tHigh = 0, tModerate = 0, tLow = 0

  for (const { name, version, advisories } of transitiveFindings) {
    const pulledInBy = [...(parentMap.get(name) ?? [])].sort()
    transitiveDetails.push({ name, version, advisories, pulledInBy })
    for (const adv of advisories) {
      switch (adv.severity) {
        case 'critical': tCritical++; break
        case 'high': tHigh++; break
        case 'moderate': tModerate++; break
        case 'low': tLow++; break
      }
    }
  }

  // Merge transitive vulns into the overall summary
  const mergedSummary = {
    critical: directReport.summary.critical + tCritical,
    high: directReport.summary.high + tHigh,
    moderate: directReport.summary.moderate + tModerate,
    low: directReport.summary.low + tLow,
  }

  if (transitiveDetails.length > 0) {
    warnings.push(
      `Found ${transitiveDetails.length} transitive dependency(ies) with known vulnerabilities. ` +
      `These are not direct dependencies but are installed in your project via the dependency tree.`,
    )
  }

  return {
    ...directReport,
    summary: mergedSummary,
    transitiveSummary: {
      totalDeps: totalTransitive,
      vulnerable: transitiveDetails.length,
      critical: tCritical,
      high: tHigh,
      moderate: tModerate,
      low: tLow,
      details: transitiveDetails,
    },
    packageManagerAudit,
    warnings: warnings.length > 0 ? warnings : undefined,
  }
}

/**
 * The version of a direct dependency installed at the project root.
 * npm lock files record the hoisted copy at node_modules/<name>; for other
 * formats it is only certain when the lock file holds a single version.
 */
function directInstalledVersion(name: string, installed: InstalledPackage[]): string | undefined {
  const copies = installed.filter(p => p.name === name)
  const hoisted = copies.find(p => p.path === `node_modules/${name}`)
  if (hoisted) return hoisted.version
  const versions = new Set(copies.map(p => p.version))
  return versions.size === 1 ? [...versions][0] : undefined
}
