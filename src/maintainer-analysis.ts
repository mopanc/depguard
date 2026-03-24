/**
 * Maintainer risk analysis for npm packages.
 *
 * Analyzes the maintainer metadata from the npm registry to flag
 * potential supply chain risks: single-maintainer bus factor,
 * free email addresses on enterprise packages, and large teams.
 *
 * Zero dependencies — only Node.js built-ins.
 */

import type { NpmPackageData, MaintainerAnalysis } from './types.js'

/** Free email domains that may indicate non-organizational ownership */
const FREE_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
  'protonmail.com', 'proton.me', 'mail.ru', 'yandex.ru', 'qq.com',
  '163.com', 'aol.com', 'icloud.com', 'zoho.com',
]

/**
 * Analyze maintainer metadata for supply chain risk signals.
 */
export function analyzeMaintainers(pkg: NpmPackageData): MaintainerAnalysis {
  const maintainers = pkg.maintainers ?? []
  const flags: string[] = []

  const time = pkg.time ?? {}
  const versionKeys = Object.keys(time).filter(k => k !== 'created' && k !== 'modified')
  const versionCount = versionKeys.length

  // Package age in days
  const createdStr = time.created ?? (versionKeys.length > 0 ? time[versionKeys[0]] : null)
  const ageInDays = createdStr
    ? (Date.now() - new Date(createdStr).getTime()) / (1000 * 60 * 60 * 24)
    : 0

  // 1. No maintainers listed
  if (maintainers.length === 0) {
    flags.push('No maintainers listed in registry metadata')
  }

  // 2. Single maintainer on mature package (bus factor risk)
  if (maintainers.length === 1 && versionCount > 20) {
    flags.push(`Single maintainer on mature package (${versionCount} versions)`)
  }

  // 3. New package (< 30 days) with single maintainer
  if (maintainers.length === 1 && ageInDays > 0 && ageInDays < 30) {
    flags.push('New package (less than 30 days old) with single maintainer')
  }

  // 4. Free email on enterprise-scale package (50+ versions)
  if (versionCount > 50) {
    for (const m of maintainers) {
      if (m.email) {
        const domain = m.email.split('@')[1]?.toLowerCase()
        if (domain && FREE_EMAIL_DOMAINS.includes(domain)) {
          flags.push(`Maintainer "${m.name}" uses free email (${domain}) on enterprise-scale package`)
        }
      }
    }
  }

  // 5. Large maintainer team (broader attack surface)
  if (maintainers.length > 10) {
    flags.push(`Large maintainer team (${maintainers.length}) increases attack surface`)
  }

  // Compute risk level based on flag count
  let riskLevel: MaintainerAnalysis['riskLevel'] = 'none'
  if (flags.length >= 3) riskLevel = 'high'
  else if (flags.length === 2) riskLevel = 'medium'
  else if (flags.length === 1) riskLevel = 'low'

  return {
    riskLevel,
    maintainerCount: maintainers.length,
    maintainers: maintainers.map(m => ({ name: m.name, email: m.email })),
    flags,
  }
}
