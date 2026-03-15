import type {
  CacheEntry,
  FetchFn,
  NpmDownloadsResponse,
  NpmPackageData,
  NpmSearchResult,
  NpmAdvisory,
} from './types.js'

const REGISTRY_URL = 'https://registry.npmjs.org'
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'
const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search'
const ADVISORIES_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'

const DEFAULT_TTL = 5 * 60 * 1000 // 5 minutes

const cache = new Map<string, CacheEntry<unknown>>()

function getCached<T>(key: string): T | null {
  const entry = cache.get(key) as CacheEntry<T> | undefined
  if (!entry) return null
  if (Date.now() > entry.expiresAt) {
    cache.delete(key)
    return null
  }
  return entry.data
}

function setCache<T>(key: string, data: T, ttl = DEFAULT_TTL): void {
  cache.set(key, { data, expiresAt: Date.now() + ttl })
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
    const res = await fetcher(`${REGISTRY_URL}/${encodeURIComponent(name)}`, {
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

/** Fetch weekly download count */
export async function fetchDownloads(
  name: string,
  fetcher: FetchFn = globalThis.fetch,
): Promise<number> {
  const key = `dl:${name}`
  const cached = getCached<number>(key)
  if (cached !== null) return cached

  try {
    const res = await fetcher(`${DOWNLOADS_URL}/${encodeURIComponent(name)}`, {
      headers: { 'Accept': 'application/json' },
    })
    if (!res.ok) return 0
    const data = (await res.json()) as NpmDownloadsResponse
    setCache(key, data.downloads)
    return data.downloads
  } catch {
    return 0
  }
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
    const res = await fetcher(`${SEARCH_URL}?${params}`, {
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
    const res = await fetcher(ADVISORIES_URL, {
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
