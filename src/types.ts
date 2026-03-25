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
  maintainerAnalysis?: MaintainerAnalysis
  publicationAnalysis?: PublicationAnalysis
  /** Security findings from static code analysis (tarball + install scripts) */
  securityFindings?: SecurityFinding[]
  /** Code analysis metadata */
  codeAnalysis?: CodeAnalysis
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

// ====== SECURITY FINDING TYPES ======

/** Category of security finding */
export type FindingCategory =
  | 'malware'
  | 'supply-chain'
  | 'vulnerability'
  | 'obfuscation'
  | 'data-exfiltration'
  | 'unexpected-behavior'
  | 'code-execution'

/** A single security finding with rich explanation */
export interface SecurityFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: FindingCategory
  title: string
  explanation: string
  evidence: string
  file: string
  recommendation: string
}

/** Result of static code analysis on a package tarball */
export interface CodeAnalysis {
  /** Whether any findings were detected */
  hasFinding: boolean
  /** All security findings from code analysis */
  findings: SecurityFinding[]
  /** Number of files analyzed */
  filesAnalyzed: number
  /** Whether the analysis was skipped (e.g. tarball too large) */
  skipped: boolean
  /** Reason for skipping, if applicable */
  skipReason?: string
}

// ====== SWEEP TYPES ======

/** Classification of why a dependency might be considered "used" even without imports */
export type DepUsageReason =
  | 'imported'
  | 'config-referenced'
  | 'npm-script'
  | 'types-only'
  | 'peer-dep'
  | 'bin-usage'

/** Result for a single dependency in sweep */
export interface SweepDepResult {
  name: string
  version: string
  status: 'unused' | 'used' | 'maybe-unused'
  reasons: DepUsageReason[]
  estimatedSizeKB: number | null
}

/** Full sweep result */
export interface SweepResult {
  projectPath: string
  totalDependencies: number
  unused: SweepDepResult[]
  maybeUnused: SweepDepResult[]
  used: number
  estimatedSavingsKB: number
  scannedFiles: number
  warnings: string[]
  /** Packages installed in node_modules but not declared in package.json */
  phantomDeps?: PhantomDep[]
  /** Always present — reminds users that results are recommendations, not commands */
  note: string
}

/** Options for sweep */
export interface SweepOptions {
  includeDevDependencies?: boolean
  excludePatterns?: string[]
}

// ====== GUARD TYPES ======

/** Decision from the guard */
export type GuardDecision = 'allow' | 'warn' | 'block'

/** Guard check result */
export interface GuardResult {
  package: string
  decision: GuardDecision
  exists: boolean
  possibleTyposquat: boolean
  similarTo: string[]
  score: number | null
  reasons: string[]
  auditSummary: {
    vulnerabilities: number
    critical: number
    high: number
    deprecated: boolean
    hasInstallScripts: boolean
    scriptAnalysisSuspicious: boolean
    license: string | null
  } | null
}

/** Options for guard */
export interface GuardOptions {
  threshold?: number
  targetLicense?: string
  block?: boolean
  fetcher?: FetchFn
}

// ====== VERIFY TYPES ======

/** Verify result (existence + typosquat check) */
export interface VerifyResult {
  package: string
  exists: boolean
  possibleTyposquat: boolean
  similarTo: string[]
  description: string | null
  version: string | null
}

/** Options for verify */
export interface VerifyOptions {
  fetcher?: FetchFn
}

// ====== PHANTOM DEPENDENCY TYPES ======

/** A dependency installed in node_modules but not declared in package.json */
export interface PhantomDep {
  name: string
  version: string | null
  estimatedSizeKB: number | null
  reason: string
}

// ====== TRANSITIVE AUDIT TYPES ======

/** A single node in the transitive dependency tree */
export interface TransitiveDepNode {
  name: string
  version: string
  depth: number
  requiredBy: string[]
  dependencies: string[]
  vulnerabilities: VulnerabilitySummary
  license: string | null
  deprecated: boolean
  circular: boolean
}

/** Result of a transitive dependency tree audit */
export interface TransitiveAuditResult {
  root: string
  rootVersion: string
  maxDepthReached: number
  maxDepthLimit: number
  totalTransitiveDeps: number
  uniquePackages: number
  nodes: TransitiveDepNode[]
  circularDeps: Array<{ from: string; to: string }>
  aggregateVulnerabilities: {
    total: number
    critical: number
    high: number
    moderate: number
    low: number
    byPackage: Array<{ name: string; depth: number; total: number; critical: number; high: number }>
  }
  warnings: string[]
}

/** Options for transitive audit */
export interface TransitiveAuditOptions {
  maxDepth?: number
  concurrency?: number
  targetLicense?: string
  fetcher?: FetchFn
}

// ====== MAINTAINER ANALYSIS TYPES ======

export type MaintainerRiskLevel = 'none' | 'low' | 'medium' | 'high'

export interface MaintainerAnalysis {
  riskLevel: MaintainerRiskLevel
  maintainerCount: number
  maintainers: Array<{ name: string; email?: string }>
  flags: string[]
}

// ====== PUBLICATION ANALYSIS TYPES ======

export type PublicationRiskLevel = 'none' | 'low' | 'medium' | 'high'

export interface PublicationAnomaly {
  type: 'burst-publishing' | 'dormant-resurrection' | 'version-jump' | 'rapid-major-bumps'
  severity: 'low' | 'medium' | 'high'
  description: string
  details: string
}

export interface PublicationAnalysis {
  riskLevel: PublicationRiskLevel
  totalVersions: number
  firstPublish: string | null
  lastPublish: string | null
  anomalies: PublicationAnomaly[]
}
