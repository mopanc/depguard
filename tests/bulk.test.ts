import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { auditBulk } from '../src/bulk.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

function makePkg(name: string) {
  return {
    name,
    description: `A ${name} package`,
    'dist-tags': { latest: '1.0.0' },
    license: 'MIT',
    time: {
      created: '2024-01-01T00:00:00.000Z',
      modified: '2025-06-01T00:00:00.000Z',
      '1.0.0': '2025-06-01T00:00:00.000Z',
    },
    versions: {
      '1.0.0': { name, version: '1.0.0', license: 'MIT', dependencies: {} },
    },
  }
}

function createMockFetch(packages: string[], advisories: Record<string, unknown> = {}): FetchFn {
  const pkgMap: Record<string, unknown> = {}
  for (const name of packages) {
    pkgMap[`registry.npmjs.org/${name}`] = makePkg(name)
  }

  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    for (const [pattern, body] of Object.entries(pkgMap)) {
      if (url.includes(pattern)) {
        return Promise.resolve({ ok: true, json: async () => body } as Response)
      }
    }
    if (url.includes('api.npmjs.org/downloads')) {
      return Promise.resolve({ ok: true, json: async () => ({ downloads: 50000 }) } as Response)
    }
    if (url.includes('security/advisories/bulk')) {
      return Promise.resolve({ ok: true, json: async () => advisories } as Response)
    }
    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('auditBulk', () => {
  it('audits multiple packages and aggregates results', async () => {
    const packages = ['pkg-a', 'pkg-b', 'pkg-c']
    const fetcher = createMockFetch(packages)
    const report = await auditBulk(packages, { fetcher })

    assert.strictEqual(report.total, 3)
    assert.strictEqual(report.clean, 3)
    assert.strictEqual(report.vulnerable, 0)
    assert.strictEqual(report.deprecated, 0)
    assert.strictEqual(report.results.length, 3)
    assert.deepStrictEqual(report.summary, { critical: 0, high: 0, moderate: 0, low: 0 })

    const names = report.results.map(r => r.name)
    assert.ok(names.includes('pkg-a'))
    assert.ok(names.includes('pkg-b'))
    assert.ok(names.includes('pkg-c'))
  })

  it('returns empty report for empty array', async () => {
    const fetcher = createMockFetch([])
    const report = await auditBulk([], { fetcher })

    assert.strictEqual(report.total, 0)
    assert.strictEqual(report.clean, 0)
    assert.strictEqual(report.vulnerable, 0)
    assert.strictEqual(report.deprecated, 0)
    assert.strictEqual(report.results.length, 0)
    assert.deepStrictEqual(report.summary, { critical: 0, high: 0, moderate: 0, low: 0 })
  })

  it('respects concurrency by batching requests', async () => {
    const packages = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    const inFlight: number[] = []
    let maxInFlight = 0

    const fetcher = ((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

      // Track concurrency for registry fetches only
      if (url.includes('registry.npmjs.org/') && !url.includes('security') && !url.includes('search')) {
        inFlight.push(1)
        if (inFlight.length > maxInFlight) maxInFlight = inFlight.length
        return new Promise<Response>(resolve => {
          setTimeout(() => {
            inFlight.pop()
            const name = url.split('/').pop() ?? 'unknown'
            resolve({ ok: true, json: async () => makePkg(name) } as Response)
          }, 10)
        })
      }
      if (url.includes('api.npmjs.org/downloads')) {
        return Promise.resolve({ ok: true, json: async () => ({ downloads: 1000 }) } as Response)
      }
      if (url.includes('security/advisories/bulk')) {
        return Promise.resolve({ ok: true, json: async () => ({}) } as Response)
      }
      return Promise.resolve({ ok: false, status: 404 } as Response)
    }) as FetchFn

    const report = await auditBulk(packages, { fetcher, concurrency: 2 })

    assert.strictEqual(report.total, 7)
    // With concurrency=2, we should never have more than 2 registry fetches in flight
    assert.ok(maxInFlight <= 2, `Expected max 2 in flight, got ${maxInFlight}`)
  })
})
