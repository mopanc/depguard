import { readFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { AuditReport, FetchFn, NpmAdvisory } from './types.js'
import { audit } from './audit.js'
import { getAllInstalledVersions } from './lockfile.js'
import { fetchBulkAdvisories } from './registry.js'

/** Options for bulk audit */
export interface BulkAuditOptions {
  targetLicense?: string
  concurrency?: number
  fetcher?: FetchFn
}

/** Vulnerability entry for a transitive dependency */
export interface TransitiveVulnerability {
  name: string
  version: string
  advisories: NpmAdvisory[]
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
  } = options

  if (packages.length === 0) {
    return { total: 0, clean: 0, vulnerable: 0, deprecated: 0, results: [], summary: { critical: 0, high: 0, moderate: 0, low: 0 } }
  }

  const results: AuditReport[] = []

  // Process in batches to respect rate limits
  for (let i = 0; i < packages.length; i += concurrency) {
    const batch = packages.slice(i, i + concurrency)
    const batchResults = await Promise.all(
      batch.map(name => audit(name, targetLicense, fetcher)),
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
 * When a lock file is present (package-lock.json or pnpm-lock.yaml):
 * - Direct deps get a full audit (vulnerabilities, code analysis, scripts, license)
 * - ALL transitive deps are checked for known vulnerabilities via the npm bulk advisory endpoint
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

  // Full audit on direct dependencies (code analysis, scripts, license, etc.)
  const directReport = await auditBulk(directPackages, bulkOptions)

  // Try to read lock file for transitive dependency vulnerability scan
  const projectDir = dirname(packageJsonPath)
  const installedVersions = getAllInstalledVersions(projectDir)

  if (installedVersions.size === 0) {
    warnings.push(
      'No lock file found (package-lock.json or pnpm-lock.yaml). ' +
      'Only direct dependencies were audited. Transitive dependencies may have vulnerabilities. ' +
      'Run "npm install" to generate a lock file for full coverage.',
    )
    return { ...directReport, packageManagerAudit, warnings }
  }

  // Identify transitive deps (in lock file but not in direct deps list)
  const directSet = new Set(directPackages)
  const transitiveDeps = new Map<string, string>()
  for (const [name, version] of installedVersions) {
    if (!directSet.has(name)) {
      transitiveDeps.set(name, version)
    }
  }

  // Bulk advisory check for ALL transitive dependencies at once
  const fetcher = bulkOptions.fetcher ?? globalThis.fetch
  const transitiveAdvisories = await fetchBulkAdvisories(transitiveDeps, fetcher)

  // Build transitive summary
  const transitiveDetails: TransitiveVulnerability[] = []
  let tCritical = 0, tHigh = 0, tModerate = 0, tLow = 0

  for (const [name, advisories] of transitiveAdvisories) {
    const version = transitiveDeps.get(name) ?? 'unknown'
    transitiveDetails.push({ name, version, advisories })
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
      totalDeps: transitiveDeps.size,
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
