import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  fetchPackage,
  fetchDownloads,
  fetchBulkDownloads,
  searchPackages,
  fetchAdvisories,
  fetchBulkAdvisories,
  fetchGitHubAdvisories,
  clearCache,
  disableDiskCache,
} from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

function mockFetch(responses: Record<string, unknown>): FetchFn {
  return (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    for (const [pattern, body] of Object.entries(responses)) {
      if (url.includes(pattern)) {
        return {
          ok: true,
          json: async () => body,
        } as Response
      }
    }
    return { ok: false, status: 404 } as Response
  }) as FetchFn
}

function failingFetch(): FetchFn {
  return (() => Promise.reject(new Error('Network error'))) as unknown as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('fetchPackage', () => {
  it('returns package data on success', async () => {
    const pkg = { name: 'test-pkg', description: 'A test', 'dist-tags': { latest: '1.0.0' }, time: {}, versions: {} }
    const fetcher = mockFetch({ 'registry.npmjs.org/test-pkg': pkg })
    const result = await fetchPackage('test-pkg', fetcher)
    assert.deepStrictEqual(result, pkg)
  })

  it('returns null on 404', async () => {
    const fetcher = mockFetch({})
    const result = await fetchPackage('nonexistent', fetcher)
    assert.strictEqual(result, null)
  })

  it('returns null on network error', async () => {
    const result = await fetchPackage('test', failingFetch())
    assert.strictEqual(result, null)
  })

  it('uses cache on second call', async () => {
    let callCount = 0
    const fetcher = ((input: string | URL | Request) => {
      callCount++
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.includes('test-pkg')) {
        return Promise.resolve({ ok: true, json: async () => ({ name: 'test-pkg', versions: {} }) } as Response)
      }
      return Promise.resolve({ ok: false, status: 404 } as Response)
    }) as FetchFn

    await fetchPackage('test-pkg', fetcher)
    await fetchPackage('test-pkg', fetcher)
    assert.strictEqual(callCount, 1)
  })
})

describe('fetchDownloads', () => {
  it('returns download count on success', async () => {
    const fetcher = mockFetch({
      'api.npmjs.org/downloads': { downloads: 50000, package: 'express' },
    })
    const result = await fetchDownloads('express', fetcher)
    assert.strictEqual(result, 50000)
  })

  it('returns 0 when npm has no stats for the package (404)', async () => {
    const result = await fetchDownloads('nope', mockFetch({}))
    assert.strictEqual(result, 0)
  })

  it('throws on network error instead of reporting 0 downloads', async () => {
    await assert.rejects(() => fetchDownloads('nope', failingFetch()))
  })

  it('retries a rate-limited response and returns the real count', async () => {
    let calls = 0
    const fetcher = (async () => {
      calls++
      if (calls < 3) {
        return { ok: false, status: 429, headers: new Headers({ 'retry-after': '0' }) } as Response
      }
      return { ok: true, status: 200, json: async () => ({ downloads: 720000000, package: 'debug' }) } as Response
    }) as unknown as FetchFn
    const result = await fetchDownloads('debug', fetcher)
    assert.strictEqual(result, 720000000)
    assert.strictEqual(calls, 3)
  })

  it('throws when still rate-limited after retries', async () => {
    let calls = 0
    const fetcher = (async () => {
      calls++
      return { ok: false, status: 429, headers: new Headers({ 'retry-after': '0' }) } as Response
    }) as unknown as FetchFn
    await assert.rejects(() => fetchDownloads('debug', fetcher), /429/)
    assert.strictEqual(calls, 4) // 1 attempt + 3 retries
  })

  it('passes an abort signal so a hung request cannot stall the audit', async () => {
    let signal: AbortSignal | undefined
    const fetcher = (async (_url: string, init?: RequestInit) => {
      signal = init?.signal ?? undefined
      return { ok: true, status: 200, json: async () => ({ downloads: 1, package: 'x' }) } as Response
    }) as unknown as FetchFn
    await fetchDownloads('x', fetcher)
    assert.ok(signal instanceof AbortSignal)
  })
})

describe('fetchBulkDownloads', () => {
  it('resolves unscoped names in one request and scoped names individually', async () => {
    const urls: string[] = []
    const fetcher = (async (input: string) => {
      urls.push(input)
      if (input.endsWith('/lodash,react')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            lodash: { downloads: 100, package: 'lodash' },
            react: { downloads: 200, package: 'react' },
          }),
        } as Response
      }
      if (input.endsWith('/%40babel%2Fcore')) {
        return { ok: true, status: 200, json: async () => ({ downloads: 300, package: '@babel/core' }) } as Response
      }
      return { ok: false, status: 404 } as Response
    }) as unknown as FetchFn

    const result = await fetchBulkDownloads(['lodash', 'react', '@babel/core'], fetcher)
    assert.deepStrictEqual(Object.fromEntries(result), { lodash: 100, react: 200, '@babel/core': 300 })
    assert.strictEqual(urls.length, 2)
  })

  it('treats a null bulk entry as 0 (no stats), like a 404', async () => {
    const fetcher = mockFetch({
      'api.npmjs.org/downloads': { lodash: { downloads: 100, package: 'lodash' }, 'gone-pkg': null },
    })
    const result = await fetchBulkDownloads(['lodash', 'gone-pkg'], fetcher)
    assert.strictEqual(result.get('gone-pkg'), 0)
  })

  it('leaves names absent (unknown) when the bulk request fails, never 0', async () => {
    const fetcher = (async () => ({ ok: false, status: 503, headers: new Headers({ 'retry-after': '0' }) } as Response)) as unknown as FetchFn
    const result = await fetchBulkDownloads(['lodash', 'react', '@babel/core'], fetcher)
    assert.strictEqual(result.size, 0)
  })

  it('populates the cache so fetchDownloads does not refetch', async () => {
    let calls = 0
    const fetcher = (async () => {
      calls++
      return {
        ok: true,
        status: 200,
        json: async () => ({ a: { downloads: 1, package: 'a' }, b: { downloads: 2, package: 'b' } }),
      } as Response
    }) as unknown as FetchFn
    await fetchBulkDownloads(['a', 'b'], fetcher)
    assert.strictEqual(await fetchDownloads('b', fetcher), 2)
    assert.strictEqual(calls, 1)
  })
})

describe('searchPackages', () => {
  it('returns search results', async () => {
    const searchResult = {
      objects: [{
        package: { name: 'foo', version: '1.0.0', description: 'a foo', date: '2025-01-01' },
        score: { final: 0.8, detail: { quality: 0.9, popularity: 0.7, maintenance: 0.8 } },
      }],
      total: 1,
    }
    const fetcher = mockFetch({ 'registry.npmjs.org/-/v1/search': searchResult })
    const result = await searchPackages('foo', 10, fetcher)
    assert.strictEqual(result.objects.length, 1)
    assert.strictEqual(result.objects[0].package.name, 'foo')
  })

  it('returns empty result on error', async () => {
    const result = await searchPackages('foo', 10, failingFetch())
    assert.strictEqual(result.objects.length, 0)
    assert.strictEqual(result.total, 0)
  })
})

describe('fetchAdvisories', () => {
  it('returns advisories on success', async () => {
    const advisories = {
      'express': [{
        id: 1,
        title: 'Test vuln',
        severity: 'high',
        url: 'https://example.com',
        vulnerable_versions: '<4.0.0',
        patched_versions: '>=4.0.0',
      }],
    }
    const fetcher = mockFetch({ 'security/advisories/bulk': advisories })
    const result = await fetchAdvisories('express', '3.0.0', fetcher)
    assert.strictEqual(result.length, 1)
    assert.strictEqual(result[0].severity, 'high')
  })

  it('returns empty array on network error', async () => {
    const result = await fetchAdvisories('test', '1.0.0', failingFetch())
    assert.deepStrictEqual(result, [])
  })
})

describe('fetchGitHubAdvisories', () => {
  it('returns advisories on success', async () => {
    const advisories = [
      {
        ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
        cve_id: 'CVE-2025-12345',
        summary: 'Test vulnerability',
        severity: 'high',
        html_url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: 'express' },
          vulnerable_version_range: '< 4.0.0',
          first_patched_version: '4.0.0',
        }],
        cwes: [{ cwe_id: 'CWE-79' }],
        cvss: { score: 7.5, vector_string: 'CVSS:3.1/AV:N' },
      },
    ]
    const fetcher = mockFetch({ 'api.github.com/advisories': advisories })

    // Wrap to add headers.get stub expected by the function
    const wrappedFetcher = (async (input: string | URL | Request, init?: RequestInit) => {
      const res = await fetcher(input, init)
      return {
        ...res,
        ok: res.ok,
        json: res.json,
        headers: { get: () => null },
      } as unknown as Response
    }) as FetchFn

    const result = await fetchGitHubAdvisories('express', wrappedFetcher)
    assert.strictEqual(result.length, 1)
    assert.strictEqual(result[0].ghsa_id, 'GHSA-xxxx-yyyy-zzzz')
    assert.strictEqual(result[0].severity, 'high')
  })

  it('returns empty array on network error', async () => {
    const result = await fetchGitHubAdvisories('test', failingFetch())
    assert.deepStrictEqual(result, [])
  })

  it('returns empty array on non-ok response', async () => {
    const fetcher = ((_input: string | URL | Request) => {
      return Promise.resolve({
        ok: false,
        status: 403,
        headers: { get: () => null },
      } as unknown as Response)
    }) as FetchFn
    const result = await fetchGitHubAdvisories('test', fetcher)
    assert.deepStrictEqual(result, [])
  })
})

describe('fetchBulkAdvisories', () => {
  it('returns advisories for vulnerable packages', async () => {
    const packages = new Map([
      ['express', '3.0.0'],
      ['lodash', '4.17.21'],
    ])
    const advisories = {
      'express': [{
        id: 1,
        title: 'Express vuln',
        severity: 'high',
        url: 'https://example.com/1',
        vulnerable_versions: '<4.0.0',
        patched_versions: '>=4.0.0',
      }],
    }
    const fetcher = mockFetch({ 'security/advisories/bulk': advisories })
    const result = await fetchBulkAdvisories(packages, fetcher)

    assert.strictEqual(result.size, 1)
    assert.ok(result.has('express'))
    const expressAdvs = result.get('express')
    assert.ok(expressAdvs)
    assert.strictEqual(expressAdvs[0].severity, 'high')
    assert.ok(!result.has('lodash')) // clean package not in results
  })

  it('returns empty map for empty input', async () => {
    const fetcher = mockFetch({})
    const result = await fetchBulkAdvisories(new Map(), fetcher)
    assert.strictEqual(result.size, 0)
  })

  it('handles network errors gracefully', async () => {
    const packages = new Map([['express', '3.0.0']])
    const result = await fetchBulkAdvisories(packages, failingFetch())
    assert.strictEqual(result.size, 0)
  })
})
