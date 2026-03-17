import type { AuditReport, FetchFn, FixSuggestion, NpmAdvisory, VulnerabilitySummary } from './types.js'
import { fetchPackage, fetchDownloads, fetchAdvisories, fetchGitHubAdvisories } from './registry.js'
import { checkLicenseCompatibility } from './license.js'
import { analyzeScripts } from './script-analysis.js'
import { satisfiesRange } from './semver.js'

const INSTALL_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall']

/** Map GitHub severity to npm severity */
function mapGitHubSeverity(severity: string): NpmAdvisory['severity'] {
  switch (severity) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'moderate'
    case 'low': return 'low'
    default: return 'low'
  }
}

/**
 * Merge npm and GitHub advisories, deduplicating by URL.
 * GitHub advisories are converted to NpmAdvisory format.
 */
function mergeAdvisories(
  npmAdvisories: NpmAdvisory[],
  ghAdvisories: Awaited<ReturnType<typeof fetchGitHubAdvisories>>,
  currentVersion: string,
): NpmAdvisory[] {
  const seen = new Set<string>()
  const merged: NpmAdvisory[] = []

  // Add npm advisories first (npm bulk endpoint already filters by version)
  for (const adv of npmAdvisories) {
    seen.add(adv.url)
    merged.push({ ...adv, source: 'npm' as const })
  }

  // Guard against non-array responses
  if (!Array.isArray(ghAdvisories)) return merged

  // Add GitHub advisories that aren't already covered
  for (const gh of ghAdvisories) {
    if (seen.has(gh.html_url)) continue

    // Also check if we already have the same GHSA by matching URL patterns
    const ghsaInNpm = npmAdvisories.some(a => a.url.includes(gh.ghsa_id))
    if (ghsaInNpm) continue

    // Filter: only include if current version is actually affected
    const vuln = gh.vulnerabilities?.[0]
    const range = vuln?.vulnerable_version_range
    if (range && !satisfiesRange(currentVersion, range)) {
      continue // Current version is NOT in the vulnerable range — skip
    }

    merged.push({
      id: parseInt(gh.ghsa_id.replace(/\D/g, '').slice(0, 8)) || 0,
      title: gh.summary,
      severity: mapGitHubSeverity(gh.severity),
      url: gh.html_url,
      vulnerable_versions: range ?? '*',
      patched_versions: vuln?.first_patched_version ?? null,
      cwe: gh.cwes?.map(c => c.cwe_id),
      cvss: gh.cvss ? { score: gh.cvss.score, vectorString: gh.cvss.vector_string } : undefined,
      source: 'github',
    })
  }

  return merged
}

/**
 * Produce a full audit report for an npm package.
 * Combines advisories from both npm registry and GitHub Advisory Database.
 * Never throws on network errors — returns a degraded report with warnings.
 */
export async function audit(
  name: string,
  targetLicense = 'MIT',
  fetcher: FetchFn = globalThis.fetch,
): Promise<AuditReport> {
  const warnings: string[] = []

  const pkg = await fetchPackage(name, fetcher)

  if (!pkg) {
    return {
      name,
      version: 'unknown',
      license: null,
      description: '',
      lastPublish: null,
      weeklyDownloads: 0,
      versionCount: 0,
      dependencyCount: 0,
      hasInstallScripts: false,
      deprecated: false,
      vulnerabilities: emptyVulnerabilities(),
      scriptAnalysis: { suspicious: false, risks: [] },
      fixSuggestions: [],
      licenseCompatibility: checkLicenseCompatibility(null, targetLicense),
      warnings: ['Could not fetch package data from npm registry'],
    }
  }

  const latestVersion = pkg['dist-tags']?.latest ?? Object.keys(pkg.versions).pop() ?? 'unknown'
  const versionData = pkg.versions[latestVersion]

  // Fetch downloads, npm advisories, and GitHub advisories concurrently
  const [downloads, npmAdvisories, ghAdvisories] = await Promise.all([
    fetchDownloads(name, fetcher).catch(() => {
      warnings.push('Could not fetch download counts')
      return 0
    }),
    fetchAdvisories(name, latestVersion, fetcher).catch(() => {
      warnings.push('Could not fetch npm security advisories')
      return []
    }),
    fetchGitHubAdvisories(name, fetcher).catch(() => {
      warnings.push('Could not fetch GitHub security advisories')
      return []
    }),
  ])

  const advisories = mergeAdvisories(npmAdvisories, ghAdvisories, latestVersion)

  const license = versionData?.license ?? pkg.license ?? null
  const deps = versionData?.dependencies ?? {}
  const scripts = versionData?.scripts ?? {}

  const hasInstallScripts = INSTALL_SCRIPT_NAMES.some(s => s in scripts)
  const deprecated = !!versionData?.deprecated
  const scriptResult = analyzeScripts(scripts as Record<string, string>)

  if (deprecated) {
    warnings.push(`Package is deprecated: ${versionData?.deprecated}`)
  }

  if (hasInstallScripts) {
    warnings.push('Package has install scripts — review carefully')
  }

  if (scriptResult.suspicious) {
    const criticalCount = scriptResult.risks.filter(r => r.severity === 'critical').length
    const highCount = scriptResult.risks.filter(r => r.severity === 'high').length
    if (criticalCount > 0) {
      warnings.push(`CRITICAL: ${criticalCount} suspicious pattern(s) found in install scripts`)
    }
    if (highCount > 0) {
      warnings.push(`WARNING: ${highCount} potentially dangerous pattern(s) found in install scripts`)
    }
  }

  const vulnerabilities: VulnerabilitySummary = {
    total: advisories.length,
    critical: advisories.filter(a => a.severity === 'critical').length,
    high: advisories.filter(a => a.severity === 'high').length,
    moderate: advisories.filter(a => a.severity === 'moderate').length,
    low: advisories.filter(a => a.severity === 'low').length,
    advisories,
  }

  // Generate fix suggestions from advisories
  const fixSuggestions: FixSuggestion[] = advisories.map(adv => ({
    vulnerability: adv.title,
    severity: adv.severity,
    currentVersion: latestVersion,
    fixVersion: adv.patched_versions ?? null,
    action: adv.patched_versions ? 'upgrade' as const : 'no-fix-available' as const,
  }))

  const licenseCompat = checkLicenseCompatibility(license, targetLicense)

  // Compute last publish date
  const times = Object.entries(pkg.time)
    .filter(([key]) => key !== 'created' && key !== 'modified')
    .map(([, val]) => val)
    .sort()
  const lastPublish = times.length > 0 ? times[times.length - 1] : null

  return {
    name,
    version: latestVersion,
    license: typeof license === 'string' ? license : null,
    description: pkg.description ?? '',
    lastPublish,
    weeklyDownloads: downloads,
    versionCount: Object.keys(pkg.versions).length,
    dependencyCount: Object.keys(deps).length,
    hasInstallScripts,
    deprecated,
    vulnerabilities,
    scriptAnalysis: scriptResult,
    fixSuggestions,
    licenseCompatibility: licenseCompat,
    warnings,
  }
}

function emptyVulnerabilities(): VulnerabilitySummary {
  return { total: 0, critical: 0, high: 0, moderate: 0, low: 0, advisories: [] }
}
