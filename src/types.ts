/** Fetch function signature, injectable for testing */
export type FetchFn = typeof globalThis.fetch

/** npm registry package metadata (abbreviated) */
export interface NpmPackageData {
  name: string
  description: string
  'dist-tags': Record<string, string>
  time: Record<string, string>
  license?: string
  versions: Record<string, NpmVersionData>
  keywords?: string[]
  homepage?: string
  repository?: { type: string; url: string }
  maintainers?: Array<{ name: string; email?: string }>
}

export interface NpmVersionData {
  name: string
  version: string
  license?: string
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  scripts?: Record<string, string>
  deprecated?: string
}

/** npm registry search result */
export interface NpmSearchResult {
  objects: Array<{
    package: {
      name: string
      version: string
      description: string
      keywords?: string[]
      date: string
      links: { npm?: string; homepage?: string; repository?: string }
      publisher: { username: string }
    }
    score: {
      final: number
      detail: { quality: number; popularity: number; maintenance: number }
    }
  }>
  total: number
}

/** npm audit advisory */
export interface NpmAdvisory {
  id: number
  title: string
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical'
  url: string
  vulnerable_versions: string
  patched_versions: string | null
  cwe?: string[]
  cvss?: { score: number; vectorString: string }
  source?: 'npm' | 'github'
}

/** GitHub Advisory Database response */
export interface GitHubAdvisory {
  ghsa_id: string
  cve_id: string | null
  summary: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  html_url: string
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string }
    vulnerable_version_range: string
    first_patched_version: string | null
  }>
  cwes: Array<{ cwe_id: string }>
  cvss: { score: number; vector_string: string } | null
}

/** npm downloads response */
export interface NpmDownloadsResponse {
  downloads: number
  package: string
  start: string
  end: string
}

/** Script analysis risk */
export interface ScriptRisk {
  script: string
  pattern: string
  severity: 'critical' | 'high' | 'moderate'
  description: string
}

/** Script analysis result */
export interface ScriptAnalysis {
  suspicious: boolean
  risks: ScriptRisk[]
}

/** Fix suggestion for a vulnerability */
export interface FixSuggestion {
  vulnerability: string
  severity: string
  currentVersion: string
  fixVersion: string | null
  action: 'upgrade' | 'no-fix-available'
}

/** Audit report for a package */
export interface AuditReport {
  name: string
  version: string
  license: string | null
  description: string
  lastPublish: string | null
  weeklyDownloads: number
  versionCount: number
  dependencyCount: number
  hasInstallScripts: boolean
  deprecated: boolean
  vulnerabilities: VulnerabilitySummary
  scriptAnalysis: ScriptAnalysis
  fixSuggestions: FixSuggestion[]
  licenseCompatibility: LicenseCompatibility
  warnings: string[]
}

export interface VulnerabilitySummary {
  total: number
  critical: number
  high: number
  moderate: number
  low: number
  advisories: NpmAdvisory[]
}

export interface LicenseCompatibility {
  compatible: boolean
  license: string | null
  targetLicense: string
  reason: string
}

/** Score breakdown */
export interface ScoreResult {
  name: string
  total: number
  breakdown: {
    security: number
    maintenance: number
    popularity: number
    license: number
    dependencies: number
  }
  warnings: string[]
}

/** Weight configuration for scoring */
export interface ScoreWeights {
  security: number
  maintenance: number
  popularity: number
  license: number
  dependencies: number
}

/** Search result entry */
export interface SearchEntry {
  name: string
  version: string
  description: string
  score: number
  keywords: string[]
  date: string
}

/** Search options */
export interface SearchOptions {
  limit?: number
  targetLicense?: string
  minScore?: number
  fetcher?: FetchFn
}

/** Native Node.js alternative */
export interface NativeAlternativeInfo {
  api: string
  example: string
  minNodeVersion: string
}

/** Advisor recommendation */
export interface Recommendation {
  intent: string
  action: 'install' | 'caution' | 'write-from-scratch' | 'use-native'
  package: string | null
  score: number | null
  nativeAlternative: NativeAlternativeInfo | null
  alternatives: Array<{ name: string; score: number }>
  reasoning: string
  warnings: string[]
}

/** Advisor options */
export interface AdvisorOptions {
  threshold?: number
  targetLicense?: string
  limit?: number
  fetcher?: FetchFn
}

/** Cache entry with TTL */
export interface CacheEntry<T> {
  data: T
  expiresAt: number
}
