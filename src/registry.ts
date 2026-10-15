import type {
  CacheEntry,
  FetchFn,
  GitHubAdvisory,
  NpmDownloadsResponse,
  NpmPackageData,
  NpmSearchResult,
  NpmAdvisory,
} from './types.js'
import { diskGet, diskSet, disableDiskCache } from './disk-cache.js'

export { disableDiskCache }

const REGISTRY_URL = 'https://registry.npmjs.org'
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'
const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search'
const ADVISORIES_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
const GITHUB_ADVISORIES_URL = 'https://api.github.com/advisories'

/**
 * Read GitHub token from environment (if available) for higher rate limits.
 * Token access is intentional — depguard needs it for GitHub Advisory API.
 */
function getGitHubToken(): string | null {
  try {
    return process.env.GITHUB_TOKEN || process.env.DEPGUARD_GITHUB_TOKEN || null
  } catch {
    return null
  }
}

const DEFAULT_TTL = 5 * 60 * 1000 // 5 minutes

/** Abort any single request after this long — one hung socket must not stall a whole audit */
const REQUEST_TIMEOUT_MS = 15_000
/** Retries for 429 / 5xx responses from npm endpoints */
const MAX_RETRIES = 3
const MAX_RETRY_DELAY_MS = 10_000
/** api.npmjs.org accepts up to 128 unscoped packages per bulk downloads lookup */
const BULK_DOWNLOADS_BATCH = 128

function withTimeout(init: RequestInit = {}): RequestInit {
  return { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }
}

function isRetryable(status: number): boolean {
  return status === 429 || status >= 500
}

function retryDelayMs(res: Response, attempt: number): number {
  const retryAfter = Number(res.headers?.get?.('retry-after'))
  const ms = Number.isFinite(retryAfter) && retryAfter >= 0 ? retryAfter * 1000 : 1000 * 2 ** attempt
  return Math.min(ms, MAX_RETRY_DELAY_MS)
}

/**
 * fetch with a per-request timeout, retrying rate-limited (429) and server
 * error (5xx) responses with backoff. Returns the last response received.
 */
async function fetchWithRetry(fetcher: FetchFn, url: string, init: RequestInit = {}): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetcher(url, withTimeout(init))
    if (!isRetryable(res.status) || attempt >= MAX_RETRIES) return res
    await new Promise(resolve => setTimeout(resolve, retryDelayMs(res, attempt)))
  }
}

const cache = new Map<string, CacheEntry<unknown>>()

function getCached<T>(key: string): T | null {
  // Check in-memory first
  const entry = cache.get(key) as CacheEntry<T> | undefined
  if (entry) {
    if (Date.now() > entry.expiresAt) {
      cache.delete(key)
    } else {
      return entry.data
    }
  }
  // Fall back to disk cache (24h TTL)
  return diskGet<T>(key)
}

function setCache<T>(key: string, data: T, ttl = DEFAULT_TTL): void {
  cache.set(key, { data, expiresAt: Date.now() + ttl })
  // Also persist to disk for cross-session cache
  diskSet(key, data)
}

/** Clear the in-memory cache */
export function clearCache(): void {
  cache.clear()
}

/** Fetch package metadata from npm registry */
export async function fetchPackage(
  name: string,
  fetcher: FetchFn = globalThis.fetch,
): Promise<NpmPackageData | null> {
  const key = `pkg:${name}`
  const cached = getCached<NpmPackageData>(key)
  if (cached) return cached

  try {
    const res = await fetchWithRetry(fetcher, `${REGISTRY_URL}/${encodeURIComponent(name)}`, {
      headers: { 'Accept': 'application/json' },
    })
    if (!res.ok) return null
    const data = (await res.json()) as NpmPackageData
    setCache(key, data)
    return data
  } catch {
    return null
  }
}

/**
 * Fetch weekly download count.
 * Throws when the count cannot be determined (rate limit, network, timeout) so
 * callers can tell "unknown" apart from a genuine 0. A 404 means npm has no
 * download stats for the package, which is a real answer: 0.
 */
export async function fetchDownloads(
  name: string,
  fetcher: FetchFn = globalThis.fetch,
): Promise<number> {
  const key = `dl:${name}`
  const cached = getCached<number>(key)
  if (cached !== null) return cached

  const res = await fetchWithRetry(fetcher, `${DOWNLOADS_URL}/${encodeURIComponent(name)}`, {
    headers: { 'Accept': 'application/json' },
  })
  if (res.status === 404) return 0
  if (!res.ok) throw new Error(`npm downloads API returned HTTP ${res.status} for ${name}`)
  const data = (await res.json()) as NpmDownloadsResponse
  setCache(key, data.downloads)
  return data.downloads
}

/**
 * Fetch weekly download counts for many packages, using the bulk endpoint for
 * unscoped names (scoped names are not supported in bulk and go one by one).
 * Results are cached, so a later fetchDownloads() for the same name is free.
 *
 * Returns only the names whose count was determined. A name absent from the
 * map means "unknown", never 0.
 */
export async function fetchBulkDownloads(
  names: string[],
  fetcher: FetchFn = globalThis.fetch,
): Promise<Map<string, number>> {
  const result = new Map<string, number>()
  const unscoped: string[] = []
  const scoped: string[] = []

  for (const name of new Set(names)) {
    const cached = getCached<number>(`dl:${name}`)
    if (cached !== null) result.set(name, cached)
    else (name.startsWith('@') ? scoped : unscoped).push(name)
  }

  for (let i = 0; i < unscoped.length; i += BULK_DOWNLOADS_BATCH) {
    const batch = unscoped.slice(i, i + BULK_DOWNLOADS_BATCH)
    // A single-name "bulk" lookup returns the non-keyed response shape
    if (batch.length === 1) {
      scoped.push(batch[0])
      continue
    }
    try {
      const res = await fetchWithRetry(fetcher, `${DOWNLOADS_URL}/${batch.map(encodeURIComponent).join(',')}`, {
        headers: { 'Accept': 'application/json' },
      })
      if (!res.ok) continue
      const data = (await res.json()) as Record<string, NpmDownloadsResponse | null>
      for (const name of batch) {
        if (!(name in data)) continue
        // null = npm has no stats for this name, same meaning as a 404
        const downloads = data[name]?.downloads ?? 0
        setCache(`dl:${name}`, downloads)
        result.set(name, downloads)
      }
    } catch {
      // Leave this batch unresolved — absent names are reported as unknown
    }
  }

  for (const name of scoped) {
    try {
      result.set(name, await fetchDownloads(name, fetcher))
    } catch {
      // Unknown — leave absent
    }
  }

  return result
}

/** Search npm registry */
export async function searchPackages(
  keywords: string,
  limit = 10,
  fetcher: FetchFn = globalThis.fetch,
): Promise<NpmSearchResult> {
  const key = `search:${keywords}:${limit}`
  const cached = getCached<NpmSearchResult>(key)
  if (cached) return cached

  const empty: NpmSearchResult = { objects: [], total: 0 }

  try {
    const params = new URLSearchParams({ text: keywords, size: String(limit) })
    const res = await fetchWithRetry(fetcher, `${SEARCH_URL}?${params}`, {
      headers: { 'Accept': 'application/json' },
    })
    if (!res.ok) return empty
    const data = (await res.json()) as NpmSearchResult
    setCache(key, data)
    return data
  } catch {
    return empty
  }
}

/** Fetch security advisories for a package via the bulk endpoint */
export async function fetchAdvisories(
  name: string,
  version: string,
  fetcher: FetchFn = globalThis.fetch,
): Promise<NpmAdvisory[]> {
  const key = `adv:${name}@${version}`
  const cached = getCached<NpmAdvisory[]>(key)
  if (cached) return cached

  try {
    const res = await fetchWithRetry(fetcher, ADVISORIES_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [name]: [version] }),
    })
    if (!res.ok) return []
    const data = (await res.json()) as Record<string, NpmAdvisory[]>
    const advisories = data[name] ?? []
    setCache(key, advisories)
    return advisories
  } catch {
    return []
  }
}

/**
 * Fetch security advisories for many packages at once via the npm bulk endpoint.
 * Accepts a Map<name, version> and sends them in batches (max 100 per request)
 * to avoid payload limits. Returns a Map<name, NpmAdvisory[]>.
 *
 * This is far more efficient than calling fetchAdvisories per package —
 * the npm bulk endpoint is designed for exactly this use case.
 */
export async function fetchBulkAdvisories(
  packages: Map<string, string>,
  fetcher: FetchFn = globalThis.fetch,
): Promise<Map<string, NpmAdvisory[]>> {
  const result = new Map<string, NpmAdvisory[]>()
  if (packages.size === 0) return result

  // Check cache first, collect uncached
  const uncached = new Map<string, string>()
  for (const [name, version] of packages) {
    const key = `adv:${name}@${version}`
    const cached = getCached<NpmAdvisory[]>(key)
    if (cached) {
      if (cached.length > 0) result.set(name, cached)
    } else {
      uncached.set(name, version)
    }
  }

  if (uncached.size === 0) return result

  // Batch into chunks of 100 to avoid payload limits
  const BATCH_SIZE = 100
  const entries = [...uncached.entries()]

  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE)
    const body: Record<string, string[]> = {}
    for (const [name, version] of batch) {
      body[name] = [version]
    }

    try {
      const res = await fetchWithRetry(fetcher, ADVISORIES_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) continue

      const data = (await res.json()) as Record<string, NpmAdvisory[]>

      // Cache and collect results
      for (const [name, version] of batch) {
        const advisories = data[name] ?? []
        setCache(`adv:${name}@${version}`, advisories)
        if (advisories.length > 0) {
          result.set(name, advisories)
        }
      }
    } catch {
      // Network error for this batch — skip, individual audits can retry
    }
  }

  return result
}

/** Track GitHub rate limit state */
let githubRateLimitRemaining = 60
let githubRateLimitReset = 0
let githubRateLimitExhausted = false

/** Check if GitHub rate limit has been exhausted during this session */
export function isGitHubRateLimited(): boolean {
  return githubRateLimitExhausted
}

/** Get remaining GitHub API calls */
export function getGitHubRateLimit(): { remaining: number; resetAt: number; exhausted: boolean } {
  return {
    remaining: githubRateLimitRemaining,
    resetAt: githubRateLimitReset,
    exhausted: githubRateLimitExhausted,
  }
}

/** Fetch security advisories from GitHub Advisory Database */
export async function fetchGitHubAdvisories(
  name: string,
  fetcher: FetchFn = globalThis.fetch,
): Promise<GitHubAdvisory[]> {
  const key = `ghsa:${name}`
  const cached = getCached<GitHubAdvisory[]>(key)
  if (cached) return cached

  // Skip GitHub if rate limited (reserve 5 requests as buffer)
  if (githubRateLimitRemaining <= 5 && Date.now() / 1000 < githubRateLimitReset) {
    githubRateLimitExhausted = true
    return []
  }

  try {
    const params = new URLSearchParams({
      ecosystem: 'npm',
      affects: name,
      per_page: '30',
    })
    const token = getGitHubToken()
    const headers: Record<string, string> = { 'Accept': 'application/vnd.github+json' }
    if (token) headers['Authorization'] = `Bearer ${token}`

    const res = await fetcher(`${GITHUB_ADVISORIES_URL}?${params}`, withTimeout({ headers }))

    // Track rate limit from response headers
    const remaining = res.headers?.get?.('x-ratelimit-remaining')
    const reset = res.headers?.get?.('x-ratelimit-reset')
    if (remaining) {
      const parsed = parseInt(remaining, 10)
      if (!isNaN(parsed)) githubRateLimitRemaining = parsed
    }
    if (reset) {
      const parsed = parseInt(reset, 10)
      if (!isNaN(parsed)) githubRateLimitReset = parsed
    }

    if (!res.ok) return []
    const data = (await res.json()) as GitHubAdvisory[]
    setCache(key, data)
    return data
  } catch {
    return []
  }
}
