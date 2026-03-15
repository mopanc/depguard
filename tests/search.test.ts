import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { search } from '../src/search.js'
import { clearCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

const SEARCH_FIXTURE = {
  objects: [
    {
      package: { name: 'date-fns', version: '3.0.0', description: 'Date utility', keywords: ['date'], date: '2025-01-01', links: {}, publisher: { username: 'user1' } },
      score: { final: 0.85, detail: { quality: 0.9, popularity: 0.8, maintenance: 0.85 } },
    },
    {
      package: { name: 'dayjs', version: '1.11.0', description: 'Fast date lib', keywords: ['date', 'time'], date: '2025-02-01', links: {}, publisher: { username: 'user2' } },
      score: { final: 0.75, detail: { quality: 0.8, popularity: 0.7, maintenance: 0.75 } },
    },
    {
      package: { name: 'moment', version: '2.30.0', description: 'Date library', keywords: ['date'], date: '2024-01-01', links: {}, publisher: { username: 'user3' } },
      score: { final: 0.45, detail: { quality: 0.5, popularity: 0.9, maintenance: 0.2 } },
    },
  ],
  total: 3,
}

function createSearchFetch(): FetchFn {
  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    if (url.includes('/-/v1/search')) {
      return Promise.resolve({ ok: true, json: async () => SEARCH_FIXTURE } as Response)
    }
    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache()
})

describe('search', () => {
  it('returns scored and sorted entries', async () => {
    const results = await search('date formatting', { fetcher: createSearchFetch() })

    assert.ok(results.length > 0)
    assert.strictEqual(results[0].name, 'date-fns')
    assert.strictEqual(results[0].score, 85)
    assert.strictEqual(results[1].name, 'dayjs')

    // Verify sorted by score descending
    for (let i = 1; i < results.length; i++) {
      assert.ok(results[i - 1].score >= results[i].score)
    }
  })

  it('respects limit option', async () => {
    const results = await search('date', { limit: 2, fetcher: createSearchFetch() })
    assert.ok(results.length <= 2)
  })

  it('filters by minimum score', async () => {
    const results = await search('date', { minScore: 50, fetcher: createSearchFetch() })
    for (const entry of results) {
      assert.ok(entry.score >= 50)
    }
    // moment has score 45, should be filtered
    assert.ok(!results.some(e => e.name === 'moment'))
  })

  it('returns empty array when no results', async () => {
    const fetcher = ((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.includes('search')) {
        return Promise.resolve({ ok: true, json: async () => ({ objects: [], total: 0 }) } as Response)
      }
      return Promise.resolve({ ok: false, status: 404 } as Response)
    }) as FetchFn

    const results = await search('nonexistent', { fetcher })
    assert.strictEqual(results.length, 0)
  })

  it('includes keywords and date in entries', async () => {
    const results = await search('date', { fetcher: createSearchFetch() })
    const first = results[0]

    assert.ok(Array.isArray(first.keywords))
    assert.ok(typeof first.date === 'string')
    assert.ok(typeof first.version === 'string')
  })
})
