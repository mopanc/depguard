import type { AuditReport, FetchFn, ScoreResult, ScoreWeights } from './types.js'
import { audit } from './audit.js'
import { lookupCompromised } from './advisory-db.js'

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

  let total = Math.round(
    (breakdown.security * weights.security +
      breakdown.maintenance * weights.maintenance +
      breakdown.popularity * weights.popularity +
      breakdown.license * weights.license +
      breakdown.dependencies * weights.dependencies) / totalWeight,
  )

  // Known compromised packages = total score 0, no exceptions
  if (lookupCompromised(name)) return { name, total: 0, breakdown, warnings: report.warnings }

  // Hard ceiling: packages with critical/high security scores cannot score above thresholds
  if (breakdown.security <= 15) total = Math.min(total, 30)  // Critical vulns → max 30
  else if (breakdown.security <= 40) total = Math.min(total, 50)  // High vulns → max 50

  return {
    name,
    total,
    breakdown,
    warnings: report.warnings,
  }
}

/**
 * Compute a score from an existing AuditReport without fetching again.
 * Used by bulk/project audit to include scores in condensed output.
 */
export function scoreFromReport(report: AuditReport): number {
  const weights = DEFAULT_WEIGHTS
  const breakdown = {
    security: computeSecurityScore(report),
    maintenance: computeMaintenanceScore(report),
    popularity: computePopularityScore(report),
    license: computeLicenseScore(report),
    dependencies: computeDependencyScore(report),
  }

  const totalWeight = weights.security + weights.maintenance + weights.popularity +
    weights.license + weights.dependencies

  let total = Math.round(
    (breakdown.security * weights.security +
      breakdown.maintenance * weights.maintenance +
      breakdown.popularity * weights.popularity +
      breakdown.license * weights.license +
      breakdown.dependencies * weights.dependencies) / totalWeight,
  )

  if (breakdown.security <= 15) total = Math.min(total, 30)
  else if (breakdown.security <= 40) total = Math.min(total, 50)

  return total
}

/**
 * Security: 100 = no vulns and no code analysis findings.
 * Uses exponential decay — any critical vuln caps the score at 15 max.
 * CVSS scores used when available for more accurate severity weighting.
 * Code analysis findings are INFORMATIONAL — they appear in the report
 * but do NOT reduce the security score. Only CVEs and advisory DB affect scoring.
 */
function computeSecurityScore(report: AuditReport): number {
  // Known compromised package = score 0 (advisory database)
  const compromised = lookupCompromised(report.name)
  if (compromised) return 0

  const v = report.vulnerabilities

  // Start with vulnerability-based score
  let vulnScore = 100

  if (v.total > 0) {
    // Critical vulns are a hard ceiling
    if (v.critical > 0) vulnScore = Math.max(0, 15 - (v.critical - 1) * 5)
    // High vulns cap at 40
    else if (v.high > 0) vulnScore = Math.max(0, 40 - (v.high - 1) * 10)
    else {
      // Use CVSS scores when available for more granular scoring
      let maxCvss = 0
      for (const adv of v.advisories) {
        if (adv.cvss?.score && adv.cvss.score > maxCvss) {
          maxCvss = adv.cvss.score
        }
      }

      if (maxCvss > 0) {
        vulnScore = Math.max(0, Math.round(100 - maxCvss * 10))
      } else {
        vulnScore -= v.moderate * 15
        vulnScore -= v.low * 5
        vulnScore = Math.max(0, vulnScore)
      }
    }
  }

  // NOTE: Code analysis findings (securityFindings) are NOT used in scoring.
  // They are informational — present in the audit report for the developer/agent
  // to review, but do not automatically penalize the score. This prevents false
  // positives from reducing scores of legitimate packages.

  return Math.max(0, vulnScore)
}

/**
 * Maintenance: based on recency, version history, and deprecation.
 * Stable packages with many versions get a maturity bonus to avoid
 * penalizing well-maintained LTS packages like lodash or express.
 */
function computeMaintenanceScore(report: AuditReport): number {
  if (!report.lastPublish) return 0

  const daysSincePublish = Math.floor(
    (Date.now() - new Date(report.lastPublish).getTime()) / (1000 * 60 * 60 * 24),
  )

  // Recency score: 100 if published today, 0 if >3 years ago (was 2 years — too aggressive)
  let recency = 100 - Math.min(100, Math.floor(daysSincePublish / 11))

  // Maturity bonus — packages with many versions are stable, not abandoned
  if (report.versionCount >= 10) recency = Math.min(100, recency + 15)
  if (report.versionCount >= 50) recency = Math.min(100, recency + 15)
  if (report.versionCount >= 100) recency = Math.min(100, recency + 10)

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

/**
 * Dependencies: fewer direct deps = smaller attack surface.
 * Install scripts are penalized in security scoring (scriptAnalysis),
 * so we only penalize dependency count here to avoid double-counting.
 */
function computeDependencyScore(report: AuditReport): number {
  let s = 100

  // Graduated deduction for dependency count
  if (report.dependencyCount > 5) s -= 10
  if (report.dependencyCount > 15) s -= 15
  if (report.dependencyCount > 30) s -= 25
  if (report.dependencyCount > 50) s -= 20

  // Install scripts add risk but are already scored in security dimension
  // Only a mild flag here for awareness
  if (report.hasInstallScripts) s -= 10

  return Math.max(0, s)
}
