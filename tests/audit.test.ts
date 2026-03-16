import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { audit } from '../src/audit.js'
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
    '1.0.0': '2023-01-01T00:00:00.000Z',
    '2.0.0': '2024-06-01T00:00:00.000Z',
    '2.5.0': '2025-06-01T00:00:00.000Z',
  },
  versions: {
    '1.0.0': { name: 'test-lib', version: '1.0.0', license: 'MIT', dependencies: {} },
    '2.0.0': { name: 'test-lib', version: '2.0.0', license: 'MIT', dependencies: { 'dep-a': '^1.0.0' } },
    '2.5.0': {
      name: 'test-lib',
      version: '2.5.0',
      license: 'MIT',
      dependencies: { 'dep-a': '^1.0.0', 'dep-b': '^2.0.0' },
      scripts: { build: 'tsc', test: 'jest' },
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

describe('audit', () => {
  it('produces a complete report for a healthy package', async () => {
    const report = await audit('test-lib', 'MIT', createMockFetch())

    assert.strictEqual(report.name, 'test-lib')
    assert.strictEqual(report.version, '2.5.0')
    assert.strictEqual(report.license, 'MIT')
    assert.strictEqual(report.description, 'A testing library')
    assert.strictEqual(report.weeklyDownloads, 100000)
    assert.strictEqual(report.versionCount, 3)
    assert.strictEqual(report.dependencyCount, 2)
    assert.strictEqual(report.hasInstallScripts, false)
    assert.strictEqual(report.deprecated, false)
    assert.strictEqual(report.vulnerabilities.total, 0)
    assert.strictEqual(report.licenseCompatibility.compatible, true)
    assert.strictEqual(report.warnings.length, 0)
  })

  it('reports vulnerabilities when present', async () => {
    const advisories = {
      'test-lib': [{
        id: 1, title: 'XSS', severity: 'high',
        url: 'https://example.com', vulnerable_versions: '<3.0.0', patched_versions: '>=3.0.0',
      }],
    }
    const fetcher = createMockFetch({ 'security/advisories/bulk': advisories })
    const report = await audit('test-lib', 'MIT', fetcher)

    assert.strictEqual(report.vulnerabilities.total, 1)
    assert.strictEqual(report.vulnerabilities.high, 1)
  })

  it('detects install scripts', async () => {
    const pkg = JSON.parse(JSON.stringify(FIXTURE_PKG))
    pkg.versions['2.5.0'].scripts.postinstall = 'node setup.js'
    const fetcher = createMockFetch({ 'registry.npmjs.org/test-lib': pkg })
    const report = await audit('test-lib', 'MIT', fetcher)

    assert.strictEqual(report.hasInstallScripts, true)
    assert.ok(report.warnings.some(w => w.includes('install scripts')))
  })

  it('detects deprecated packages', async () => {
    const pkg = JSON.parse(JSON.stringify(FIXTURE_PKG))
    pkg.versions['2.5.0'].deprecated = 'Use other-lib instead'
    const fetcher = createMockFetch({ 'registry.npmjs.org/test-lib': pkg })
    const report = await audit('test-lib', 'MIT', fetcher)

    assert.strictEqual(report.deprecated, true)
    assert.ok(report.warnings.some(w => w.includes('deprecated')))
  })

  it('reports license incompatibility', async () => {
    const report = await audit('test-lib', 'BSD-2-Clause', createMockFetch())
    assert.strictEqual(report.licenseCompatibility.compatible, true)
  })

  it('returns degraded report when package not found', async () => {
    const fetcher = (() => Promise.resolve({ ok: false, status: 404 } as Response)) as FetchFn
    const report = await audit('nonexistent', 'MIT', fetcher)

    assert.strictEqual(report.name, 'nonexistent')
    assert.strictEqual(report.version, 'unknown')
    assert.ok(report.warnings.length > 0)
  })

  it('returns degraded report on network error', async () => {
    const fetcher = (() => Promise.reject(new Error('offline'))) as unknown as FetchFn
    const report = await audit('test-lib', 'MIT', fetcher)

    assert.strictEqual(report.version, 'unknown')
    assert.ok(report.warnings.some(w => w.includes('Could not fetch')))
  })

  it('correctly reports last publish date', async () => {
    const report = await audit('test-lib', 'MIT', createMockFetch())
    assert.strictEqual(report.lastPublish, '2025-06-01T00:00:00.000Z')
  })
})
