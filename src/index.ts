export { audit } from './audit.js'
export { analyzeScripts } from './script-analysis.js'
export { findNativeAlternative } from './native-alternatives.js'
export { auditBulk, auditProject } from './bulk.js'
export { search } from './search.js'
export { score } from './scorer.js'
export { shouldUse } from './advisor.js'
export { guard, verify, levenshtein } from './guard.js'
export { sweep, extractImports, collectSourceFiles, detectPhantomDeps } from './sweep.js'
export { auditTransitive } from './transitive.js'
export { analyzeMaintainers } from './maintainer-analysis.js'
export { analyzePublicationTimeline } from './publication-analysis.js'
export { checkLicenseCompatibility, knownLicenses } from './license.js'
export { clearCache, fetchGitHubAdvisories, isGitHubRateLimited, getGitHubRateLimit } from './registry.js'
export { calculateSavings, estimateTokens } from './tokens.js'
export type {
  AdvisorOptions,
  AuditReport,
  CacheEntry,
  DepUsageReason,
  FetchFn,
  GitHubAdvisory,
  GuardDecision,
  GuardOptions,
  GuardResult,
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
  SweepDepResult,
  SweepOptions,
  SweepResult,
  VerifyOptions,
  VerifyResult,
  VulnerabilitySummary,
  PhantomDep,
  TransitiveDepNode,
  TransitiveAuditResult,
  TransitiveAuditOptions,
  MaintainerAnalysis,
  MaintainerRiskLevel,
  PublicationAnalysis,
  PublicationAnomaly,
  PublicationRiskLevel,
} from './types.js'
export type { TokenSavings } from './tokens.js'
export type { BulkAuditReport, BulkAuditOptions, ProjectAuditOptions } from './bulk.js'
