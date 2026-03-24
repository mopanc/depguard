/**
 * Publication timeline anomaly detection.
 *
 * Analyzes the version history of an npm package to detect patterns
 * commonly associated with supply chain attacks: burst publishing,
 * dormant account resurrection, and suspicious version jumps.
 *
 * Zero dependencies — only Node.js built-ins.
 */

import type { NpmPackageData, PublicationAnalysis, PublicationAnomaly, PublicationRiskLevel } from './types.js'

interface VersionEntry {
  version: string
  date: Date
}

/**
 * Parse the major version number from a semver string.
 */
function parseMajor(version: string): number | null {
  const clean = version.replace(/^v/, '')
  const major = parseInt(clean.split('.')[0], 10)
  return isNaN(major) ? null : major
}

/**
 * Compute overall risk level from anomalies.
 */
function computeRiskLevel(anomalies: PublicationAnomaly[]): PublicationRiskLevel {
  if (anomalies.length === 0) return 'none'
  if (anomalies.some(a => a.severity === 'high')) return 'high'
  if (anomalies.some(a => a.severity === 'medium')) return 'medium'
  return 'low'
}

/**
 * Analyze the publication timeline of an npm package for anomalies.
 * Uses the `time` field from the npm registry response.
 */
export function analyzePublicationTimeline(pkg: NpmPackageData): PublicationAnalysis {
  const time = pkg.time ?? {}

  const versions: VersionEntry[] = Object.entries(time)
    .filter(([key]) => key !== 'created' && key !== 'modified')
    .map(([version, ts]) => ({ version, date: new Date(ts) }))
    .sort((a, b) => a.date.getTime() - b.date.getTime())

  if (versions.length === 0) {
    return {
      riskLevel: 'none',
      totalVersions: 0,
      firstPublish: null,
      lastPublish: null,
      anomalies: [],
    }
  }

  const anomalies: PublicationAnomaly[] = []
  const firstPublish = versions[0].date.toISOString()
  const lastPublish = versions[versions.length - 1].date.toISOString()

  const DAY_MS = 24 * 60 * 60 * 1000
  const now = Date.now()
  const ONE_YEAR_AGO = now - 365 * DAY_MS
  const isMaturedPackage = versions.length > 50

  // 1. Burst publishing: >5 STABLE versions within 24 hours
  // Only flag bursts in the LAST 2 YEARS — old bursts are historical noise
  // Pre-release/canary versions are excluded — frameworks like React publish many per day
  const stableForBurst = versions.filter(v =>
    !v.version.includes('canary') && !v.version.includes('experimental') &&
    !v.version.includes('nightly'),
  )
  const TWO_YEARS_AGO = now - 730 * DAY_MS
  for (let i = 0; i < stableForBurst.length; i++) {
    if (stableForBurst[i].date.getTime() < TWO_YEARS_AGO) continue
    const windowStart = versions[i].date.getTime()
    let count = 0
    for (let j = i; j < stableForBurst.length; j++) {
      if (stableForBurst[j].date.getTime() - windowStart < DAY_MS) {
        count++
      } else {
        break
      }
    }
    if (count >= 6) {
      anomalies.push({
        type: 'burst-publishing',
        severity: count >= 10 ? 'high' : 'medium',
        description: `${count} versions published within 24 hours`,
        details: `Starting from ${stableForBurst[i].version} on ${stableForBurst[i].date.toISOString().slice(0, 10)}`,
      })
      break // Only report the worst burst
    }
  }

  // 2. Dormant resurrection — ONLY flag the MOST RECENT gap
  // Mature packages (50+ versions) naturally have longer gaps between releases.
  // A stable package not publishing for 2 years is normal, not suspicious.
  // Only flag if the gap is recent AND followed by sudden activity.
  const dormantThreshold = isMaturedPackage ? 730 : 365 // 2 years for mature, 1 year for new
  if (versions.length >= 2) {
    const lastIdx = versions.length - 1
    const lastGapMs = versions[lastIdx].date.getTime() - versions[lastIdx - 1].date.getTime()
    const lastGapDays = Math.floor(lastGapMs / DAY_MS)
    // Only flag if the last publish was recent (within 1 year) — meaning someone "woke up" the package
    if (lastGapDays > dormantThreshold && versions[lastIdx].date.getTime() > ONE_YEAR_AGO) {
      // For mature packages, dormant gaps are informational, not alarming
      const severity = isMaturedPackage ? 'low' : (lastGapDays > 1460 ? 'high' : 'medium')
      anomalies.push({
        type: 'dormant-resurrection',
        severity,
        description: `Package dormant for ${lastGapDays} days then republished recently`,
        details: `Gap between ${versions[lastIdx - 1].version} and ${versions[lastIdx].version}`,
      })
    }
  }

  // 3. Version jumps: major version jump > 2 (only stable versions, recent only)
  // Filter out pre-release/canary/experimental/rc versions — they create noise
  const stableVersions = versions.filter(v =>
    !v.version.includes('-') && !v.version.includes('canary') &&
    !v.version.includes('experimental') && !v.version.includes('rc') &&
    !v.version.includes('alpha') && !v.version.includes('beta'),
  )
  for (let i = 1; i < stableVersions.length; i++) {
    if (stableVersions[i].date.getTime() < TWO_YEARS_AGO) continue
    const prevMajor = parseMajor(stableVersions[i - 1].version)
    const currMajor = parseMajor(stableVersions[i].version)
    if (prevMajor !== null && currMajor !== null && currMajor - prevMajor > 2) {
      anomalies.push({
        type: 'version-jump',
        severity: currMajor - prevMajor > 5 ? 'high' : 'low',
        description: `Major version jumped from ${prevMajor} to ${currMajor}`,
        details: `${stableVersions[i - 1].version} to ${stableVersions[i].version}`,
      })
    }
  }

  return {
    riskLevel: computeRiskLevel(anomalies),
    totalVersions: versions.length,
    firstPublish,
    lastPublish,
    anomalies,
  }
}
