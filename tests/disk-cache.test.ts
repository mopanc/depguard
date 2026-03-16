import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// We need to override the CACHE_DIR before importing disk-cache.
// Since the module uses a constant, we test by importing the functions
// and temporarily monkey-patching the homedir to redirect the cache directory.
// Instead, we'll test via the public API by manipulating enable/disable
// and using a fresh import approach.

// For disk-cache tests we need to work with the actual module but control
// the cache directory. Since CACHE_DIR is derived from homedir(), we can
// set HOME env var before importing.

const TEST_CACHE_DIR = join(tmpdir(), `depguard-test-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`)

// Save original HOME and override before importing the module
const originalHome = process.env.HOME
process.env.HOME = TEST_CACHE_DIR

// Dynamic import after env override so CACHE_DIR picks up the new homedir
const { diskGet, diskSet, disableDiskCache, enableDiskCache } = await import('../src/disk-cache.js')

beforeEach(() => {
  enableDiskCache()
  // Ensure the test cache directory exists
  const cacheDir = join(TEST_CACHE_DIR, '.depguard', 'cache')
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true })
  }
})

afterEach(() => {
  // Clean up test cache directory
  const depguardDir = join(TEST_CACHE_DIR, '.depguard')
  if (existsSync(depguardDir)) {
    rmSync(depguardDir, { recursive: true, force: true })
  }
})

// Restore HOME after all tests
process.on('exit', () => {
  process.env.HOME = originalHome
  if (existsSync(TEST_CACHE_DIR)) {
    rmSync(TEST_CACHE_DIR, { recursive: true, force: true })
  }
})

describe('disk-cache', () => {
  it('diskSet and diskGet basic flow', () => {
    diskSet('test-key', { foo: 'bar', num: 42 })
    const result = diskGet<{ foo: string; num: number }>('test-key')
    assert.deepStrictEqual(result, { foo: 'bar', num: 42 })
  })

  it('diskGet returns null for expired entries', () => {
    // Set with a negative TTL so it is already expired
    diskSet('expired-key', { value: 'old' }, -1000)
    const result = diskGet('expired-key')
    assert.strictEqual(result, null)
  })

  it('diskGet returns null for missing entries', () => {
    const result = diskGet('nonexistent-key')
    assert.strictEqual(result, null)
  })

  it('disableDiskCache prevents reads and writes', () => {
    disableDiskCache()

    // Write should be silently skipped
    diskSet('blocked-key', { value: 'secret' })

    // Re-enable to verify nothing was written
    enableDiskCache()
    const result = diskGet('blocked-key')
    assert.strictEqual(result, null)

    // Also verify reads are blocked when disabled
    diskSet('readable-key', { value: 'data' })
    disableDiskCache()
    const blocked = diskGet('readable-key')
    assert.strictEqual(blocked, null)

    // Re-enable to confirm data was actually written
    enableDiskCache()
    const unblocked = diskGet<{ value: string }>('readable-key')
    assert.deepStrictEqual(unblocked, { value: 'data' })
  })
})
