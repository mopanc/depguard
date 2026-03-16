import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { shouldUse } from '../src/advisor.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

function createAdvisorFetch(packages: Array<{ name: string; score: number; license?: string; downloads?: number }>): FetchFn {
  const searchResult = {
    objects: packages.map((p, i) => ({
      package: {
        name: p.name,
        version: '1.0.0',
        description: `${p.name} package`,
        keywords: [],
        date: '2025-01-01',
        links: {},
        publisher: { username: 'author' },
      },
      score: {
        final: (packages.length - i) / packages.length,
        detail: { quality: 0.5, popularity: 0.5, maintenance: 0.5 },
      },
    })),
    total: packages.length,
  }

  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    if (url.includes('/-/v1/search')) {
      return Promise.resolve({ ok: true, json: async () => searchResult } as Response)
    }

    for (const p of packages) {
      if (url.includes(`registry.npmjs.org/${p.name}`)) {
        const recentDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
        const pkg = {
          name: p.name,
          description: `${p.name} package`,
          'dist-tags': { latest: '1.0.0' },
          license: p.license ?? 'MIT',
          time: { '1.0.0': recentDate },
          versions: {
            '1.0.0': {
              name: p.name,
              version: '1.0.0',
              license: p.license ?? 'MIT',
              dependencies: {},
              scripts: {},
            },
          },
        }
        return Promise.resolve({ ok: true, json: async () => pkg } as Response)
      }
    }

    if (url.includes('api.npmjs.org/downloads')) {
      // Try to match package name from URL
      for (const p of packages) {
        if (url.includes(p.name)) {
          return Promise.resolve({ ok: true, json: async () => ({ downloads: p.downloads ?? 100000 }) } as Response)
        }
      }
      return Promise.resolve({ ok: true, json: async () => ({ downloads: 100000 }) } as Response)
    }

    if (url.includes('advisories')) {
      return Promise.resolve({ ok: true, json: async () => ({}) } as Response)
    }

    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('shouldUse', () => {
  it('recommends "install" for high-quality packages', async () => {
    const fetcher = createAdvisorFetch([
      { name: 'great-lib', score: 90, downloads: 1000000 },
    ])
    const rec = await shouldUse('date formatting', { fetcher })

    assert.strictEqual(rec.action, 'install')
    assert.strictEqual(rec.package, 'great-lib')
    assert.ok(rec.score !== null && rec.score >= 60)
    assert.strictEqual(rec.intent, 'date formatting')
  })

  it('recommends "write-from-scratch" when no packages found', async () => {
    const fetcher = ((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.includes('search')) {
        return Promise.resolve({ ok: true, json: async () => ({ objects: [], total: 0 }) } as Response)
      }
      return Promise.resolve({ ok: false, status: 404 } as Response)
    }) as FetchFn

    const rec = await shouldUse('very specific niche thing', { fetcher })

    assert.strictEqual(rec.action, 'write-from-scratch')
    assert.strictEqual(rec.package, null)
    assert.strictEqual(rec.score, null)
  })

  it('recommends "caution" or "write-from-scratch" for low-quality packages', async () => {
    const fetcher = createAdvisorFetch([
      { name: 'bad-lib', score: 20, license: 'UNLICENSED', downloads: 5 },
    ])
    const rec = await shouldUse('something', { fetcher, threshold: 90 })

    assert.ok(
      rec.action === 'write-from-scratch' || rec.action === 'caution',
      `Expected caution or write-from-scratch but got "${rec.action}"`,
    )
  })

  it('provides alternatives in the result', async () => {
    const fetcher = createAdvisorFetch([
      { name: 'lib-a', score: 90, downloads: 500000 },
      { name: 'lib-b', score: 80, downloads: 200000 },
      { name: 'lib-c', score: 70, downloads: 100000 },
    ])
    const rec = await shouldUse('utility', { fetcher, limit: 3 })

    assert.ok(rec.alternatives.length > 0)
    for (const alt of rec.alternatives) {
      assert.ok(typeof alt.name === 'string')
      assert.ok(typeof alt.score === 'number')
    }
  })

  it('respects custom threshold', async () => {
    const fetcher = createAdvisorFetch([
      { name: 'medium-lib', score: 55, downloads: 50000 },
    ])

    const rec1 = await shouldUse('something', { fetcher, threshold: 90 })
    // With high threshold, medium lib might get caution or write-from-scratch
    assert.ok(rec1.action !== 'install' || rec1.score !== null && rec1.score >= 90)

    clearCache(); disableDiskCache()
    const rec2 = await shouldUse('something', { fetcher, threshold: 30 })
    // With low threshold, should recommend install
    assert.strictEqual(rec2.action, 'install')
  })

  it('includes reasoning in the result', async () => {
    const fetcher = createAdvisorFetch([
      { name: 'some-lib', score: 80, downloads: 100000 },
    ])
    const rec = await shouldUse('http client', { fetcher })

    assert.ok(typeof rec.reasoning === 'string')
    assert.ok(rec.reasoning.length > 0)
  })
})
