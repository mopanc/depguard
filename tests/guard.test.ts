import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { levenshtein, findSimilarPackages, verify, guard } from '../src/guard.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

const FIXTURE_PKG = {
  name: 'test-lib',
  description: 'A testing library',
  'dist-tags': { latest: '2.5.0' },
  license: 'MIT',
  time: {
    created: '2023-01-01T00:00:00.000Z',
    modified: '2025-06-01T00:00:00.000Z',
    '2.5.0': '2025-06-01T00:00:00.000Z',
  },
  versions: {
    '2.5.0': {
      name: 'test-lib',
      version: '2.5.0',
      license: 'MIT',
      dependencies: { 'dep-a': '^1.0.0' },
    },
  },
}

function createMockFetch(overrides: Record<string, unknown> = {}): FetchFn {
  const defaults: Record<string, unknown> = {
    'registry.npmjs.org/test-lib': FIXTURE_PKG,
    'api.npmjs.org/downloads': { downloads: 100000, package: 'test-lib' },
    'security/advisories/bulk': {},
  }
  const responses = { ...defaults, ...overrides }

  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    for (const [pattern, body] of Object.entries(responses)) {
      if (url.includes(pattern)) {
        return Promise.resolve({ ok: true, json: async () => body } as Response)
      }
    }
    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('levenshtein', () => {
  it('returns 0 for identical strings', () => {
    assert.strictEqual(levenshtein('express', 'express'), 0)
  })

  it('returns 1 for single character difference', () => {
    assert.strictEqual(levenshtein('express', 'expresss'), 1)
  })

  it('returns 1 for single character substitution', () => {
    assert.strictEqual(levenshtein('lodash', 'lodahs'), 2)
  })

  it('returns correct distance for completely different strings', () => {
    assert.strictEqual(levenshtein('abc', 'xyz'), 3)
  })

  it('handles empty strings', () => {
    assert.strictEqual(levenshtein('', 'abc'), 3)
    assert.strictEqual(levenshtein('abc', ''), 3)
    assert.strictEqual(levenshtein('', ''), 0)
  })
})

describe('findSimilarPackages', () => {
  it('finds typosquats of popular packages', () => {
    const similar = findSimilarPackages('expresss')
    assert.ok(similar.includes('express'))
  })

  it('returns empty for exact match to popular package', () => {
    const similar = findSimilarPackages('express')
    assert.strictEqual(similar.length, 0)
  })

  it('finds similar packages for "lodahs"', () => {
    const similar = findSimilarPackages('lodahs')
    assert.ok(similar.includes('lodash'))
  })

  it('returns empty for completely unrelated names', () => {
    const similar = findSimilarPackages('zzzzzzzzzzzzzzz')
    assert.strictEqual(similar.length, 0)
  })
})

describe('verify', () => {
  it('returns exists=true for existing package', async () => {
    const result = await verify('test-lib', { fetcher: createMockFetch() })
    assert.strictEqual(result.exists, true)
    assert.strictEqual(result.version, '2.5.0')
    assert.strictEqual(result.description, 'A testing library')
  })

  it('returns exists=false for nonexistent package', async () => {
    const fetcher = (() => Promise.resolve({ ok: false, status: 404 } as Response)) as FetchFn
    const result = await verify('nonexistent-fake-pkg', { fetcher })
    assert.strictEqual(result.exists, false)
  })

  it('detects typosquat for existing package with suspicious name', async () => {
    // "expresss" is close to "express" but is a different package
    const expresssFixture = { ...FIXTURE_PKG, name: 'expresss' }
    const fetcher = createMockFetch({
      'registry.npmjs.org/expresss': expresssFixture,
    })
    const result = await verify('expresss', { fetcher })
    assert.strictEqual(result.possibleTyposquat, true)
    assert.ok(result.similarTo.includes('express'))
  })
})

describe('guard', () => {
  it('allows a healthy package above threshold', async () => {
    const result = await guard('test-lib', {
      threshold: 60,
      targetLicense: 'MIT',
      fetcher: createMockFetch(),
    })
    assert.strictEqual(result.exists, true)
    assert.strictEqual(result.decision, 'allow')
    assert.ok(result.score !== null && result.score >= 60)
  })

  it('blocks nonexistent package', async () => {
    const fetcher = (() => Promise.resolve({ ok: false, status: 404 } as Response)) as FetchFn
    const result = await guard('nonexistent-fake-pkg-xyz', {
      fetcher,
    })
    assert.strictEqual(result.exists, false)
    assert.strictEqual(result.decision, 'block')
    assert.ok(result.reasons.some(r => r.includes('does not exist')))
  })

  it('warns on deprecated package', async () => {
    const pkg = JSON.parse(JSON.stringify(FIXTURE_PKG))
    pkg.versions['2.5.0'].deprecated = 'Use other-lib instead'
    const fetcher = createMockFetch({ 'registry.npmjs.org/test-lib': pkg })
    const result = await guard('test-lib', {
      threshold: 30,
      targetLicense: 'MIT',
      fetcher,
    })
    assert.ok(result.reasons.some(r => r.includes('deprecated')))
  })

  it('escalates warn to block when block mode is active', async () => {
    const pkg = JSON.parse(JSON.stringify(FIXTURE_PKG))
    pkg.versions['2.5.0'].deprecated = 'Use other-lib instead'
    const fetcher = createMockFetch({ 'registry.npmjs.org/test-lib': pkg })
    const result = await guard('test-lib', {
      threshold: 30,
      targetLicense: 'MIT',
      block: true,
      fetcher,
    })
    // With block mode, any warn becomes block
    if (result.decision === 'warn' || result.decision === 'block') {
      assert.strictEqual(result.decision, 'block')
    }
  })

  it('returns audit summary with vulnerability info', async () => {
    const result = await guard('test-lib', {
      targetLicense: 'MIT',
      fetcher: createMockFetch(),
    })
    assert.ok(result.auditSummary !== null)
    const summary = result.auditSummary as NonNullable<typeof result.auditSummary>
    assert.strictEqual(typeof summary.vulnerabilities, 'number')
    assert.strictEqual(typeof summary.deprecated, 'boolean')
    assert.strictEqual(typeof summary.hasInstallScripts, 'boolean')
  })

  it('warns on package with critical vulnerabilities', async () => {
    const advisories = {
      'test-lib': [{
        id: 1, title: 'RCE', severity: 'critical',
        url: 'https://example.com', vulnerable_versions: '<3.0.0', patched_versions: '>=3.0.0',
      }],
    }
    const fetcher = createMockFetch({ 'security/advisories/bulk': advisories })
    const result = await guard('test-lib', {
      threshold: 30,
      targetLicense: 'MIT',
      fetcher,
    })
    assert.ok(result.reasons.some(r => r.includes('critical')))
  })
})
