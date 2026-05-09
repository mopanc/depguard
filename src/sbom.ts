/**
 * SBOM (Software Bill of Materials) generation in CycloneDX 1.6 format.
 *
 * Reads the project's lock file to enumerate installed components, generates
 * a CycloneDX 1.6 BOM document with PURLs, integrity hashes, and (optionally)
 * VEX vulnerability data sourced from the existing audit pipeline.
 *
 * Zero dependencies — implements CycloneDX serialization natively against
 * the published JSON schema rather than via @cyclonedx/cyclonedx-library,
 * preserving the project's zero-runtime-dep guarantee.
 */

import { existsSync, readFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { getAllInstalledVersions } from './lockfile.js'
import { auditProject } from './bulk.js'
import type { BulkAuditReport, ProjectAuditOptions } from './bulk.js'
import type { NpmAdvisory } from './types.js'
import { DEPGUARD_VERSION } from './version.js'
import { knownLicenses } from './license.js'
import type {
  Component,
  CycloneDXBom,
  Dependency,
  Hash,
  HashAlgorithm,
  License,
  Vulnerability,
  VulnerabilityAffect,
  VulnerabilityRating,
  VulnerabilitySeverity,
} from './sbom-types.js'

export interface SBOMOptions extends ProjectAuditOptions {
  /** Include VEX vulnerability data (runs auditProject under the hood). Default: false. */
  includeVex?: boolean
  /** BOM revision number (CycloneDX `version` field). Default: 1. */
  bomVersion?: number
  /** ISO 8601 timestamp for the BOM. Default: now. Mostly for tests/snapshots. */
  timestamp?: string
  /** Override the serial number. Default: random UUID. Mostly for tests/snapshots. */
  serialNumber?: string
}

/**
 * Generate a CycloneDX 1.6 SBOM document for an npm project.
 *
 * Pass the path to a `package.json` file. The matching lock file is read
 * alongside to resolve installed versions for the full dependency graph
 * (direct + transitive). The returned object is JSON-serializable and
 * conforms to the CycloneDX 1.6 schema.
 */
export async function generateSBOM(
  packageJsonPath: string,
  options: SBOMOptions = {},
): Promise<CycloneDXBom> {
  const {
    includeVex = false,
    bomVersion = 1,
    timestamp = new Date().toISOString(),
    serialNumber = `urn:uuid:${randomUUID()}`,
  } = options

  const projectDir = dirname(packageJsonPath)
  const projectPkg = readJsonOrThrow(packageJsonPath, 'package.json')

  const installed = getAllInstalledVersions(projectDir)
  const integrityMap = readNpmIntegrity(projectDir)

  // Root component: the project this SBOM describes
  const rootName = (projectPkg.name as string | undefined) ?? basename(projectDir)
  const rootVersion = (projectPkg.version as string | undefined) ?? '0.0.0'
  const rootRef = makePurl(rootName, rootVersion)
  const rootComponent: Component = {
    'bom-ref': rootRef,
    type: 'application',
    name: rootName,
    version: rootVersion,
    purl: rootRef,
  }
  if (typeof projectPkg.description === 'string' && projectPkg.description.length > 0) {
    rootComponent.description = projectPkg.description
  }
  // SPDX id set used to classify license strings into license.id vs name.
  const spdxIds = new Set(knownLicenses())

  if (typeof projectPkg.license === 'string' && projectPkg.license.length > 0) {
    rootComponent.licenses = [licenseStringToCycloneDX(projectPkg.license, spdxIds)]
  } else {
    const fromLegacy = extractLegacyLicenseFields(projectPkg, spdxIds)
    if (fromLegacy) rootComponent.licenses = fromLegacy
  }

  // Component map (name -> bom-ref) for dependency graph + VEX wiring
  const refByName = new Map<string, string>()
  refByName.set(rootName, rootRef)

  const components: Component[] = []
  for (const [name, version] of installed) {
    if (name === rootName) continue // don't duplicate the root
    const purl = makePurl(name, version)
    const comp: Component = {
      'bom-ref': purl,
      type: 'library',
      name,
      version,
      scope: 'required',
      purl,
    }
    const hash = integrityMap.get(`${name}@${version}`)
    if (hash) comp.hashes = [hash]
    // Closes #63: populate per-component licenses by reading
    // node_modules/<name>/package.json. Falls back to an explicit UNKNOWN
    // entry so downstream license-compliance scanners (FOSSA, ScanCode,
    // Syft) can detect missing license data instead of treating absence
    // as compatibility.
    const licenses = extractLicensesFromInstalledPkg(name, projectDir, spdxIds)
    comp.licenses = licenses ?? [{ license: { name: 'UNKNOWN' } }]
    components.push(comp)
    refByName.set(name, purl)
  }

  // Dependency graph: for the MVP we record root → direct deps only.
  // Lock-file-derived transitive edges can be added in a follow-up;
  // CycloneDX accepts a partial graph as long as ref/dependsOn match real components.
  const directNames = new Set<string>([
    ...Object.keys((projectPkg.dependencies as Record<string, string> | undefined) ?? {}),
    ...(options.includeDevDependencies
      ? Object.keys((projectPkg.devDependencies as Record<string, string> | undefined) ?? {})
      : []),
  ])
  const rootDependsOn: string[] = []
  for (const name of directNames) {
    const ref = refByName.get(name)
    if (ref) rootDependsOn.push(ref)
  }
  const dependencies: Dependency[] = [{ ref: rootRef, dependsOn: rootDependsOn }]

  // Optional: VEX section
  let vulnerabilities: Vulnerability[] | undefined
  if (includeVex) {
    const audit = await auditProject(packageJsonPath, options)
    const vex = buildVexFromAudit(audit, refByName)
    if (vex.length > 0) vulnerabilities = vex
  }

  const bom: CycloneDXBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber,
    version: bomVersion,
    metadata: {
      timestamp,
      tools: {
        components: [{
          type: 'application',
          name: 'depguard',
          version: DEPGUARD_VERSION,
          publisher: 'Jorge Morais',
          externalReferences: [
            { type: 'website', url: 'https://depguard.dev' },
            { type: 'vcs', url: 'https://github.com/mopanc/depguard' },
          ],
        }],
      },
      component: rootComponent,
    },
    components,
    dependencies,
  }

  if (vulnerabilities) bom.vulnerabilities = vulnerabilities

  return bom
}

/**
 * Build a Package URL (PURL) for an npm package.
 * Spec: https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst#npm
 *
 * Format: `pkg:npm/<name>@<version>` for unscoped, `pkg:npm/%40<scope>/<name>@<version>` for scoped.
 */
export function makePurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const slashIdx = name.indexOf('/')
    if (slashIdx > 0) {
      const scope = name.slice(0, slashIdx)
      const pkgName = name.slice(slashIdx + 1)
      return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(pkgName)}@${encodeURIComponent(version)}`
    }
  }
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
}

/**
 * Read npm's package-lock.json and extract integrity hashes per `<name>@<version>`.
 *
 * npm stores hashes as `sha512-<base64>` (Subresource Integrity format);
 * CycloneDX requires hex. We convert here. Returns empty map for non-npm projects
 * or when no integrity field is present.
 */
function readNpmIntegrity(projectDir: string): Map<string, Hash> {
  const result = new Map<string, Hash>()
  const lockPath = join(projectDir, 'package-lock.json')
  if (!existsSync(lockPath)) return result

  try {
    const lock = JSON.parse(readFileSync(lockPath, 'utf-8'))
    if (!lock.packages || typeof lock.packages !== 'object') return result

    for (const [key, entry] of Object.entries(lock.packages as Record<string, unknown>)) {
      if (!key) continue
      const name = key.replace(/^node_modules\//, '')
      if (name.includes('node_modules/')) continue
      const e = entry as { version?: string; integrity?: string }
      if (!e.version || !e.integrity) continue
      const hash = parseIntegrity(e.integrity)
      if (hash) result.set(`${name}@${e.version}`, hash)
    }
  } catch {
    /* ignore — partial map is fine */
  }

  return result
}

/**
 * Parse an SRI integrity string like `sha512-<base64>` into a CycloneDX Hash with hex content.
 * If the string contains multiple hashes (space-separated), we take the strongest known one.
 */
export function parseIntegrity(integrity: string): Hash | null {
  const algMap: Record<string, HashAlgorithm> = {
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha512: 'SHA-512',
  }
  const preference: Array<keyof typeof algMap> = ['sha512', 'sha384', 'sha256', 'sha1']

  // Split on whitespace, parse each, then pick by preference
  const parsed: Array<{ algKey: string; alg: HashAlgorithm; content: string }> = []
  for (const part of integrity.split(/\s+/)) {
    const dashIdx = part.indexOf('-')
    if (dashIdx < 0) continue
    const algKey = part.slice(0, dashIdx).toLowerCase()
    const b64 = part.slice(dashIdx + 1)
    const alg = algMap[algKey]
    if (!alg || !b64) continue
    try {
      const hex = Buffer.from(b64, 'base64').toString('hex')
      if (hex) parsed.push({ algKey, alg, content: hex })
    } catch {
      /* ignore unparseable */
    }
  }

  for (const pref of preference) {
    const hit = parsed.find(p => p.algKey === pref)
    if (hit) return { alg: hit.alg, content: hit.content }
  }
  return null
}

/**
 * Map depguard's audit output into CycloneDX VEX vulnerability entries,
 * deduplicated by (id, affected ref) so the same CVE doesn't appear twice
 * when it surfaces via both direct and transitive scans.
 */
function buildVexFromAudit(audit: BulkAuditReport, refByName: Map<string, string>): Vulnerability[] {
  const out: Vulnerability[] = []

  for (const r of audit.results) {
    for (const adv of r.vulnerabilities.advisories) {
      out.push(advisoryToVuln(adv, r.name, r.version, refByName))
    }
  }

  for (const t of audit.transitiveSummary?.details ?? []) {
    for (const adv of t.advisories) {
      out.push(advisoryToVuln(adv, t.name, t.version, refByName))
    }
  }

  const seen = new Set<string>()
  return out.filter(v => {
    const key = `${v.id}|${v.affects?.[0]?.ref ?? ''}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function advisoryToVuln(
  adv: NpmAdvisory,
  pkgName: string,
  pkgVersion: string,
  refByName: Map<string, string>,
): Vulnerability {
  const ref = refByName.get(pkgName) ?? makePurl(pkgName, pkgVersion)
  const id = extractAdvisoryId(adv) ?? `npm-${adv.id}`

  const sourceName = adv.source === 'github' ? 'GitHub Advisory Database' : 'npm Advisory Database'
  const ratings: VulnerabilityRating[] = [{
    source: { name: sourceName },
    severity: mapSeverity(adv.severity),
  }]
  if (adv.cvss) {
    ratings[0].score = adv.cvss.score
    ratings[0].method = 'CVSSv31'
    ratings[0].vector = adv.cvss.vectorString
  }

  const cwes = adv.cwe
    ?.map(c => parseInt(c.replace(/\D/g, ''), 10))
    .filter(n => Number.isFinite(n) && n > 0)

  const affects: VulnerabilityAffect[] = [{
    ref,
    versions: [{ range: adv.vulnerable_versions, status: 'affected' }],
  }]

  const vuln: Vulnerability = {
    id,
    source: { name: sourceName, url: adv.url },
    ratings,
    description: adv.title,
    affects,
  }
  if (cwes && cwes.length > 0) vuln.cwes = cwes
  if (adv.patched_versions) vuln.recommendation = `Upgrade to ${adv.patched_versions}`

  return vuln
}

/** Pick the canonical advisory identifier — GHSA preferred, then CVE, else npm fallback. */
function extractAdvisoryId(adv: NpmAdvisory): string | null {
  const ghsa = adv.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)
  if (ghsa) return ghsa[0].toUpperCase()
  const cve = adv.url.match(/CVE-\d{4}-\d{4,}/i)
  if (cve) return cve[0].toUpperCase()
  return null
}

function mapSeverity(s: NpmAdvisory['severity']): VulnerabilitySeverity {
  switch (s) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'moderate': return 'medium'
    case 'low': return 'low'
    case 'info': return 'info'
    default: return 'unknown'
  }
}

function readJsonOrThrow(path: string, name: string): Record<string, unknown> {
  if (!existsSync(path)) throw new Error(`${name} not found at ${path}`)
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch (err) {
    throw new Error(`Failed to parse ${name}: ${(err as Error).message}`)
  }
}

/**
 * Convert a raw license string (from package.json `license` field) into a
 * CycloneDX 1.6 License entry. Picks the right shape:
 *
 * - SPDX expression (contains OR/AND/WITH or wrapped in parens) → `expression`
 * - Valid SPDX identifier → `license.id`
 * - Anything else (free-form text, e.g. "SEE LICENSE IN LICENSE.txt",
 *   "UNLICENSED") → `license.name`
 */
function licenseStringToCycloneDX(raw: string, spdxIds: Set<string>): License {
  const trimmed = raw.trim()
  if (!trimmed) return { license: { name: 'UNKNOWN' } }
  if (/\s+(OR|AND|WITH)\s+/i.test(trimmed) || trimmed.startsWith('(')) {
    return { expression: trimmed }
  }
  if (spdxIds.has(trimmed)) return { license: { id: trimmed } }
  return { license: { name: trimmed } }
}

/**
 * Read `node_modules/<name>/package.json` and produce CycloneDX `licenses[]`.
 * Returns undefined when the package is not installed, the file is unreadable,
 * or no license fields are present. The caller decides the fallback (typically
 * an explicit UNKNOWN entry).
 *
 * Handles three formats found in the wild:
 *   - `license: "MIT"` (modern, npm-recommended)
 *   - `license: { type, url }` (early npm convention, still found)
 *   - `licenses: [{ type, url }, ...]` (legacy array form, deprecated but
 *     present in older packages)
 *
 * Closes #63.
 */
function extractLicensesFromInstalledPkg(
  name: string,
  projectDir: string,
  spdxIds: Set<string>,
): License[] | undefined {
  const pkgPath = join(projectDir, 'node_modules', ...name.split('/'), 'package.json')
  if (!existsSync(pkgPath)) return undefined

  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
  } catch {
    return undefined
  }

  return extractLegacyLicenseFields(pkg, spdxIds)
}

/**
 * Pull a CycloneDX `licenses[]` array out of a parsed package.json object,
 * trying the three license shapes in order. Used both by per-component
 * extraction and by the root component fallback.
 */
function extractLegacyLicenseFields(
  pkg: Record<string, unknown>,
  spdxIds: Set<string>,
): License[] | undefined {
  // Modern: license as string
  if (typeof pkg.license === 'string' && pkg.license.length > 0) {
    return [licenseStringToCycloneDX(pkg.license, spdxIds)]
  }

  // Early-npm: license as object
  if (pkg.license && typeof pkg.license === 'object') {
    const obj = pkg.license as { type?: unknown; name?: unknown }
    const id = typeof obj.type === 'string' ? obj.type
      : typeof obj.name === 'string' ? obj.name
      : null
    if (id && id.length > 0) return [licenseStringToCycloneDX(id, spdxIds)]
  }

  // Legacy: licenses as array
  if (Array.isArray(pkg.licenses)) {
    const out: License[] = []
    for (const item of pkg.licenses) {
      if (!item || typeof item !== 'object') continue
      const obj = item as { type?: unknown; name?: unknown }
      const id = typeof obj.type === 'string' ? obj.type
        : typeof obj.name === 'string' ? obj.name
        : null
      if (id && id.length > 0) out.push(licenseStringToCycloneDX(id, spdxIds))
    }
    if (out.length > 0) return out
  }

  return undefined
}
