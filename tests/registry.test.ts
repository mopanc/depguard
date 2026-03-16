import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  fetchPackage,
  fetchDownloads,
  searchPackages,
  fetchAdvisories,
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

  it('returns 0 on failure', async () => {
    const result = await fetchDownloads('nope', failingFetch())
    assert.strictEqual(result, 0)
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
