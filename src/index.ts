export { audit } from './audit.js'
export { analyzeScripts } from './script-analysis.js'
export { findNativeAlternative } from './native-alternatives.js'
export { auditBulk, auditProject } from './bulk.js'
export { search } from './search.js'
export { score } from './scorer.js'
export { shouldUse } from './advisor.js'
export { checkLicenseCompatibility, knownLicenses } from './license.js'
export { clearCache, fetchGitHubAdvisories } from './registry.js'
export { calculateSavings, estimateTokens } from './tokens.js'
export type {
  AdvisorOptions,
  AuditReport,
  CacheEntry,
  FetchFn,
  GitHubAdvisory,
  LicenseCompatibility,
  NpmAdvisory,
  ScriptAnalysis,
  ScriptRisk,
  NpmDownloadsResponse,
  NpmPackageData,
  NpmSearchResult,
  NpmVersionData,
  Recommendation,
  ScoreResult,
  ScoreWeights,
  SearchEntry,
  SearchOptions,
  VulnerabilitySummary,
} from './types.js'
export type { TokenSavings } from './tokens.js'
export type { BulkAuditReport, BulkAuditOptions, ProjectAuditOptions } from './bulk.js'
