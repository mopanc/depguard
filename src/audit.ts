import type { AuditReport, FetchFn, VulnerabilitySummary } from './types.js'
import { fetchPackage, fetchDownloads, fetchAdvisories } from './registry.js'
import { checkLicenseCompatibility } from './license.js'

const INSTALL_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall']

/**
 * Produce a full audit report for an npm package.
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
      licenseCompatibility: checkLicenseCompatibility(null, targetLicense),
      warnings: ['Could not fetch package data from npm registry'],
    }
  }

  const latestVersion = pkg['dist-tags']?.latest ?? Object.keys(pkg.versions).pop() ?? 'unknown'
  const versionData = pkg.versions[latestVersion]

  // Fetch downloads and advisories concurrently
  const [downloads, advisories] = await Promise.all([
    fetchDownloads(name, fetcher).catch(() => {
      warnings.push('Could not fetch download counts')
      return 0
    }),
    fetchAdvisories(name, latestVersion, fetcher).catch(() => {
      warnings.push('Could not fetch security advisories')
      return []
    }),
  ])

  const license = versionData?.license ?? pkg.license ?? null
  const deps = versionData?.dependencies ?? {}
  const scripts = versionData?.scripts ?? {}

  const hasInstallScripts = INSTALL_SCRIPT_NAMES.some(s => s in scripts)
  const deprecated = !!versionData?.deprecated

  if (deprecated) {
    warnings.push(`Package is deprecated: ${versionData?.deprecated}`)
  }

  if (hasInstallScripts) {
    warnings.push('Package has install scripts — review carefully')
  }

  const vulnerabilities: VulnerabilitySummary = {
    total: advisories.length,
    critical: advisories.filter(a => a.severity === 'critical').length,
    high: advisories.filter(a => a.severity === 'high').length,
    moderate: advisories.filter(a => a.severity === 'moderate').length,
    low: advisories.filter(a => a.severity === 'low').length,
    advisories,
  }

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
    licenseCompatibility: licenseCompat,
    warnings,
  }
}

function emptyVulnerabilities(): VulnerabilitySummary {
  return { total: 0, critical: 0, high: 0, moderate: 0, low: 0, advisories: [] }
}
