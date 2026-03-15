export { audit } from './audit.js'
export { search } from './search.js'
export { score } from './scorer.js'
export { shouldUse } from './advisor.js'
export { checkLicenseCompatibility, knownLicenses } from './license.js'
export { clearCache } from './registry.js'
export { calculateSavings, estimateTokens } from './tokens.js'
export type {
  AdvisorOptions,
  AuditReport,
  CacheEntry,
  FetchFn,
  LicenseCompatibility,
  NpmAdvisory,
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
