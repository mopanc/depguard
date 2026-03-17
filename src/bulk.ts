import { readFileSync } from 'node:fs'
import type { AuditReport, FetchFn } from './types.js'
import { audit } from './audit.js'

/** Options for bulk audit */
export interface BulkAuditOptions {
  targetLicense?: string
  concurrency?: number
  fetcher?: FetchFn
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
 * Reads the file, extracts dependency names, and runs bulk audit.
 */
export async function auditProject(
  packageJsonPath: string,
  options: ProjectAuditOptions = {},
): Promise<BulkAuditReport> {
  const { includeDevDependencies = false, ...bulkOptions } = options

  const raw = readFileSync(packageJsonPath, 'utf-8')
  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
    license?: string
  }

  const deps = Object.keys(pkg.dependencies ?? {})
  const devDeps = includeDevDependencies ? Object.keys(pkg.devDependencies ?? {}) : []
  const allPackages = [...new Set([...deps, ...devDeps])]

  // Use project license as target if not explicitly set
  if (!bulkOptions.targetLicense && pkg.license) {
    bulkOptions.targetLicense = pkg.license
  }

  return auditBulk(allPackages, bulkOptions)
}
