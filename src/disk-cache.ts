import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createHash } from 'node:crypto'

const CACHE_DIR = join(homedir(), '.depguard', 'cache')
const DEFAULT_TTL = 24 * 60 * 60 * 1000 // 24 hours

let diskCacheEnabled = true

/** Disable disk cache (used in tests) */
export function disableDiskCache(): void {
  diskCacheEnabled = false
}

/** Enable disk cache */
export function enableDiskCache(): void {
  diskCacheEnabled = true
}

interface DiskCacheEntry<T> {
  data: T
  expiresAt: number
  createdAt: string
}

function ensureCacheDir(): void {
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true })
  }
}

function cacheKey(key: string): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 16)
}

function cachePath(key: string): string {
  return join(CACHE_DIR, `${cacheKey(key)}.json`)
}

/** Read from disk cache. Returns null if missing or expired. */
export function diskGet<T>(key: string): T | null {
  if (!diskCacheEnabled) return null
  try {
    const path = cachePath(key)
    if (!existsSync(path)) return null

    const raw = readFileSync(path, 'utf-8')
    const entry = JSON.parse(raw) as DiskCacheEntry<T>

    if (Date.now() > entry.expiresAt) {
      return null
    }

    return entry.data
  } catch {
    return null
  }
}

/** Write to disk cache with TTL (default 24h). */
export function diskSet<T>(key: string, data: T, ttl = DEFAULT_TTL): void {
  if (!diskCacheEnabled) return
  try {
    ensureCacheDir()
    const entry: DiskCacheEntry<T> = {
      data,
      expiresAt: Date.now() + ttl,
      createdAt: new Date().toISOString(),
    }
    writeFileSync(cachePath(key), JSON.stringify(entry), 'utf-8')
  } catch {
    // Silently fail — cache is best-effort
  }
}

/** Remove expired cache files from disk. */
export function cleanupDiskCache(): number {
  if (!diskCacheEnabled) return 0
  try {
    if (!existsSync(CACHE_DIR)) return 0
    const files = readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'))
    let removed = 0
    for (const file of files) {
      try {
        const path = join(CACHE_DIR, file)
        const raw = readFileSync(path, 'utf-8')
        const entry = JSON.parse(raw) as DiskCacheEntry<unknown>
        if (Date.now() > entry.expiresAt) {
          unlinkSync(path)
          removed++
        }
      } catch {
        // Skip corrupted files
      }
    }
    return removed
  } catch {
    return 0
  }
}
