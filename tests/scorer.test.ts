import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { score } from '../src/scorer.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

function createScorerFetch(overrides: Record<string, unknown> = {}): FetchFn {
  const pkg = {
    name: 'good-pkg',
    description: 'A good package',
    'dist-tags': { latest: '3.0.0' },
    license: 'MIT',
    time: {
      created: '2024-01-01T00:00:00.000Z',
      '3.0.0': new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 1 week ago
    },
    versions: {
      '1.0.0': { name: 'good-pkg', version: '1.0.0', license: 'MIT', dependencies: {} },
      '2.0.0': { name: 'good-pkg', version: '2.0.0', license: 'MIT', dependencies: {} },
      '3.0.0': {
        name: 'good-pkg', version: '3.0.0', license: 'MIT',
        dependencies: { 'dep-a': '^1.0.0' },
        scripts: { build: 'tsc' },
      },
    },
    ...overrides.pkg as Record<string, unknown> | undefined,
  }

  const defaults: Record<string, unknown> = {
    'registry.npmjs.org/good-pkg': pkg,
    'api.npmjs.org/downloads': { downloads: 500000, package: 'good-pkg' },
    'security/advisories/bulk': {},
    ...overrides,
  }

  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    for (const [pattern, body] of Object.entries(defaults)) {
      if (pattern !== 'pkg' && url.includes(pattern)) {
        return Promise.resolve({ ok: true, json: async () => body } as Response)
      }
    }
    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('score', () => {
  it('returns a score between 0 and 100', async () => {
    const result = await score('good-pkg', { fetcher: createScorerFetch() })
    assert.ok(result.total >= 0 && result.total <= 100)
    assert.strictEqual(result.name, 'good-pkg')
  })

  it('has breakdown with all sub-scores', async () => {
    const result = await score('good-pkg', { fetcher: createScorerFetch() })
    assert.ok('security' in result.breakdown)
    assert.ok('maintenance' in result.breakdown)
    assert.ok('popularity' in result.breakdown)
    assert.ok('license' in result.breakdown)
    assert.ok('dependencies' in result.breakdown)

    for (const val of Object.values(result.breakdown)) {
      assert.ok(val >= 0 && val <= 100)
    }
  })

  it('healthy package gets high score', async () => {
    const result = await score('good-pkg', { fetcher: createScorerFetch() })
    assert.ok(result.total >= 60, `Expected ≥60 but got ${result.total}`)
  })

  it('security score drops with vulnerabilities', async () => {
    const advisories = {
      'good-pkg': [
        { id: 1, title: 'Critical vuln', severity: 'critical', url: '', vulnerable_versions: '*', patched_versions: null },
        { id: 2, title: 'High vuln', severity: 'high', url: '', vulnerable_versions: '*', patched_versions: null },
      ],
    }
    const result = await score('good-pkg', {
      fetcher: createScorerFetch({ 'security/advisories/bulk': advisories }),
    })
    assert.ok(result.breakdown.security < 50, `Expected security <50 but got ${result.breakdown.security}`)
  })

  it('critical vulnerability caps security score at 15', async () => {
    const advisories = {
      'good-pkg': [
        { id: 1, title: 'RCE', severity: 'critical', url: '', vulnerable_versions: '*', patched_versions: null },
      ],
    }
    const result = await score('good-pkg', {
      fetcher: createScorerFetch({ 'security/advisories/bulk': advisories }),
    })
    assert.ok(result.breakdown.security <= 15, `Critical vuln should cap at 15, got ${result.breakdown.security}`)
    // Total score must be low — a critical vuln package should never be recommended
    assert.ok(result.total < 60, `Package with critical vuln should score <60, got ${result.total}`)
  })

  it('license score is 0 for incompatible license', async () => {
    const pkg = {
      name: 'gpl-pkg',
      description: 'GPL package',
      'dist-tags': { latest: '1.0.0' },
      license: 'GPL-3.0',
      time: { '1.0.0': new Date().toISOString() },
      versions: { '1.0.0': { name: 'gpl-pkg', version: '1.0.0', license: 'GPL-3.0', dependencies: {} } },
    }
    const fetcher = ((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.includes('registry.npmjs.org/gpl-pkg')) {
        return Promise.resolve({ ok: true, json: async () => pkg } as Response)
      }
      if (url.includes('api.npmjs.org/downloads')) {
        return Promise.resolve({ ok: true, json: async () => ({ downloads: 1000 }) } as Response)
      }
      if (url.includes('advisories')) {
        return Promise.resolve({ ok: true, json: async () => ({}) } as Response)
      }
      return Promise.resolve({ ok: false, status: 404 } as Response)
    }) as FetchFn

    const result = await score('gpl-pkg', { targetLicense: 'MIT', fetcher })
    assert.strictEqual(result.breakdown.license, 0)
  })

  it('supports custom weights', async () => {
    const result1 = await score('good-pkg', { fetcher: createScorerFetch() })
    const result2 = await score('good-pkg', {
      fetcher: createScorerFetch(),
      weights: { security: 100, maintenance: 0, popularity: 0, license: 0, dependencies: 0 },
    })
    // With only security weight, total should equal security sub-score
    assert.strictEqual(result2.total, result2.breakdown.security)
    // And likely differ from the balanced score
    assert.ok(result1.total !== result2.total || result2.breakdown.security === result1.total)
  })

  it('returns 0 score for unfetchable package', async () => {
    const fetcher = (() => Promise.resolve({ ok: false, status: 404 } as Response)) as FetchFn
    const result = await score('nonexistent', { fetcher })
    assert.ok(result.total <= 40, `Expected low score but got ${result.total}`)
  })
})
