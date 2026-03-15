import type { AuditReport, FetchFn, ScoreResult, ScoreWeights } from './types.js'
import { audit } from './audit.js'

const DEFAULT_WEIGHTS: ScoreWeights = {
  security: 30,
  maintenance: 25,
  popularity: 20,
  license: 15,
  dependencies: 10,
}

/**
 * Score a package from 0-100 based on security, maintenance, popularity,
 * license compatibility, and dependency health.
 */
export async function score(
  name: string,
  options: {
    targetLicense?: string
    weights?: Partial<ScoreWeights>
    fetcher?: FetchFn
  } = {},
): Promise<ScoreResult> {
  const {
    targetLicense = 'MIT',
    weights: customWeights,
    fetcher = globalThis.fetch,
  } = options

  const weights = { ...DEFAULT_WEIGHTS, ...customWeights }
  const report = await audit(name, targetLicense, fetcher)

  const breakdown = {
    security: computeSecurityScore(report),
    maintenance: computeMaintenanceScore(report),
    popularity: computePopularityScore(report),
    license: computeLicenseScore(report),
    dependencies: computeDependencyScore(report),
  }

  const totalWeight = weights.security + weights.maintenance + weights.popularity +
    weights.license + weights.dependencies

  const total = Math.round(
    (breakdown.security * weights.security +
      breakdown.maintenance * weights.maintenance +
      breakdown.popularity * weights.popularity +
      breakdown.license * weights.license +
      breakdown.dependencies * weights.dependencies) / totalWeight,
  )

  return {
    name,
    total,
    breakdown,
    warnings: report.warnings,
  }
}

/** Security: 100 = no vulns, deduct for each severity level */
function computeSecurityScore(report: AuditReport): number {
  const v = report.vulnerabilities
  let s = 100
  s -= v.critical * 40
  s -= v.high * 20
  s -= v.moderate * 10
  s -= v.low * 5
  return Math.max(0, s)
}

/** Maintenance: based on recency of last publish and version count */
function computeMaintenanceScore(report: AuditReport): number {
  if (!report.lastPublish) return 0

  const daysSincePublish = Math.floor(
    (Date.now() - new Date(report.lastPublish).getTime()) / (1000 * 60 * 60 * 24),
  )

  // Recency score: 100 if published today, 0 if >2 years ago
  let recency = 100 - Math.min(100, Math.floor(daysSincePublish / 7.3))

  // Bonus for having multiple versions (active development)
  if (report.versionCount >= 10) recency = Math.min(100, recency + 10)
  if (report.versionCount >= 50) recency = Math.min(100, recency + 10)

  // Penalty for deprecation
  if (report.deprecated) recency = Math.floor(recency * 0.3)

  return Math.max(0, recency)
}

/** Popularity: logarithmic scale based on weekly downloads */
function computePopularityScore(report: AuditReport): number {
  if (report.weeklyDownloads <= 0) return 0

  // log10 scale: 100 downloads = ~20, 10k = ~40, 1M = ~60, 100M = ~80, 1B = ~100
  const logDownloads = Math.log10(report.weeklyDownloads)
  return Math.min(100, Math.round(logDownloads * 10))
}

/** License: 100 if compatible, 0 if not */
function computeLicenseScore(report: AuditReport): number {
  return report.licenseCompatibility.compatible ? 100 : 0
}

/** Dependencies: fewer deps = better, install scripts are a big red flag */
function computeDependencyScore(report: AuditReport): number {
  let s = 100

  // Deduct for dependency count
  if (report.dependencyCount > 5) s -= 10
  if (report.dependencyCount > 15) s -= 15
  if (report.dependencyCount > 30) s -= 25

  // Major penalty for install scripts
  if (report.hasInstallScripts) s -= 30

  return Math.max(0, s)
}
