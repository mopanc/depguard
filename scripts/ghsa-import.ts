/**
 * Pure conversion of GitHub Security Advisories into advisory-db incidents.
 * Kept separate from refresh-advisory-db.ts so the false-positive rules are
 * unit-tested (policy `depguard-false-positive-aversion-policy`).
 */

export type IncidentType = 'supply-chain' | 'account-hijack' | 'maintainer-sabotage' | 'typosquat' | 'protestware'

export interface Incident {
  version: string
  type: IncidentType
  date: string
  cve: string | null
  description: string
  origin?: 'curated' | 'ghsa' | 'osv'
}

export interface GhsaAdvisory {
  ghsa_id: string
  cve_id: string | null
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  published_at: string
  withdrawn_at: string | null
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string }
    vulnerable_version_range: string | null
  }>
}

export interface PackageIncident {
  name: string
  incident: Incident
  severity: 'critical' | 'high' | 'low'
}

/**
 * Advisories about packages that were only exposed THROUGH a malicious
 * dependency (e.g. "MetaMask SDK indirectly exposed via malicious debug@4.4.2")
 * are not themselves malicious. The malicious dependency has its own advisory,
 * so importing these would only flag legitimate versions.
 */
export const INDIRECT_EXPOSURE = /\bindirect(?:ly)?\b|\bexposed via\b|\bimpacting\b/i

/** Ranges that mean "every version" are stored as the 'all' sentinel. */
export function normalizeVersionRange(range: string | null): string {
  const r = (range ?? '').trim()
  if (r === '' || /^>=?\s*0(?:\.0(?:\.0)?)?$/.test(r)) return 'all'
  return r
}

export function mapSeverity(s: GhsaAdvisory['severity']): PackageIncident['severity'] {
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  return 'low'
}

export function incidentId(adv: Pick<GhsaAdvisory, 'cve_id' | 'ghsa_id'>): string {
  return adv.cve_id ?? adv.ghsa_id
}

/**
 * One incident per npm package named in the advisory. Every vulnerable range
 * for the same package is kept (joined with "||"); earlier versions of the
 * importer kept only the first npm entry and silently dropped the rest.
 */
export function advisoryToIncidents(adv: GhsaAdvisory): { incidents: PackageIncident[]; skipped?: string } {
  if (adv.withdrawn_at) return { incidents: [], skipped: 'withdrawn' }
  if (INDIRECT_EXPOSURE.test(adv.summary ?? '')) return { incidents: [], skipped: 'indirect exposure' }

  const ranges = new Map<string, string[]>()
  for (const v of adv.vulnerabilities ?? []) {
    if (v.package?.ecosystem !== 'npm' || !v.package.name) continue
    const list = ranges.get(v.package.name) ?? []
    list.push(normalizeVersionRange(v.vulnerable_version_range))
    ranges.set(v.package.name, list)
  }

  const incidents: PackageIncident[] = []
  for (const [name, list] of ranges) {
    const unique = [...new Set(list)]
    incidents.push({
      name,
      severity: mapSeverity(adv.severity),
      incident: {
        version: unique.includes('all') ? 'all' : unique.join(' || '),
        type: 'supply-chain',
        date: adv.published_at.split('T')[0],
        cve: incidentId(adv),
        description: adv.summary || `Malware advisory ${adv.ghsa_id}`,
        origin: 'ghsa',
      },
    })
  }
  return { incidents }
}
