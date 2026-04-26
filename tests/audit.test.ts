import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { audit, mergeAdvisories } from '../src/audit.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn, GitHubAdvisory } from '../src/types.js'

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

  it('audits a specific version when provided', async () => {
    // Version 2.0.0 has 1 dep, 2.5.0 has 2 deps — use that to verify correct version is picked
    const report = await audit('test-lib', 'MIT', createMockFetch(), '2.0.0')
    assert.strictEqual(report.version, '2.0.0')
    assert.strictEqual(report.dependencyCount, 1) // 2.0.0 has only dep-a
  })

  it('falls back to latest metadata when version not in registry', async () => {
    const report = await audit('test-lib', 'MIT', createMockFetch(), '9.9.9')
    assert.strictEqual(report.version, '9.9.9')
    assert.ok(report.warnings.some(w => w.includes('9.9.9 not found')))
    // Should still work using latest version metadata
    assert.strictEqual(report.dependencyCount, 2) // falls back to 2.5.0 data
  })

  it('uses latest when version not provided', async () => {
    const report = await audit('test-lib', 'MIT', createMockFetch())
    assert.strictEqual(report.version, '2.5.0') // latest
  })
})

// ───────────────────────────────────────────────────────────────────────────
// Regression tests for the multi-package GHSA bug (CVE-2023-22578 false
// positive on sequelize@6.37.8). When a GHSA spans multiple npm packages
// with different vulnerable_version_ranges, mergeAdvisories must pick the
// entry matching the package being audited — not blindly use [0].
// ───────────────────────────────────────────────────────────────────────────

function buildSequelizeStyleGhsa(): GitHubAdvisory {
  return {
    ghsa_id: 'GHSA-f598-mfpv-gmfx',
    cve_id: 'CVE-2023-22578',
    summary: 'Sequelize - Default support for raw attributes when using parentheses',
    severity: 'critical',
    html_url: 'https://github.com/advisories/GHSA-f598-mfpv-gmfx',
    vulnerabilities: [
      {
        // Note: @sequelize/core is intentionally first so that vulnerabilities[0]
        // would yield the wrong range for the `sequelize` package — exactly the
        // ordering observed in the real GitHub Advisory API response.
        package: { ecosystem: 'npm', name: '@sequelize/core' },
        vulnerable_version_range: '< 7.0.0-alpha.20',
        first_patched_version: '7.0.0-alpha.20',
      },
      {
        package: { ecosystem: 'npm', name: 'sequelize' },
        vulnerable_version_range: '< 6.29.0',
        first_patched_version: '6.29.0',
      },
    ],
    cwes: [{ cwe_id: 'CWE-89' }],
    cvss: { score: 10.0, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
  }
}

describe('mergeAdvisories — multi-package GHSA handling', () => {
  it('uses the matching package entry, not [0], when auditing sequelize at a patched version', () => {
    const gh = [buildSequelizeStyleGhsa()]
    // sequelize@6.37.8 is patched (>= 6.29.0). The advisory should be filtered out.
    const merged = mergeAdvisories([], gh, '6.37.8', 'sequelize')
    assert.strictEqual(merged.length, 0, 'sequelize@6.37.8 must not be flagged — patched in 6.29.0')
  })

  it('flags sequelize at a vulnerable v6 version using the sequelize-specific range', () => {
    const gh = [buildSequelizeStyleGhsa()]
    // sequelize@6.20.0 is < 6.29.0, so vulnerable per the npm/sequelize entry.
    const merged = mergeAdvisories([], gh, '6.20.0', 'sequelize')
    assert.strictEqual(merged.length, 1)
    // The captured range and patch must come from the sequelize entry, not @sequelize/core.
    assert.strictEqual(merged[0].vulnerable_versions, '< 6.29.0')
    assert.strictEqual(merged[0].patched_versions, '6.29.0')
    assert.strictEqual(merged[0].severity, 'critical')
  })

  it('flags @sequelize/core at a vulnerable version using the @sequelize/core-specific range', () => {
    const gh = [buildSequelizeStyleGhsa()]
    const merged = mergeAdvisories([], gh, '6.5.0', '@sequelize/core')
    assert.strictEqual(merged.length, 1)
    assert.strictEqual(merged[0].vulnerable_versions, '< 7.0.0-alpha.20')
    assert.strictEqual(merged[0].patched_versions, '7.0.0-alpha.20')
  })

  it('does not regress single-package advisories', () => {
    const gh: GitHubAdvisory[] = [{
      ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
      cve_id: null,
      summary: 'Some bug',
      severity: 'high',
      html_url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'lodash' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21',
      }],
      cwes: [],
      cvss: null,
    }]
    assert.strictEqual(mergeAdvisories([], gh, '4.17.20', 'lodash').length, 1)
    assert.strictEqual(mergeAdvisories([], gh, '4.17.21', 'lodash').length, 0)
  })

  it('falls back to [0] defensively when no entry matches the audited name', () => {
    // This shouldn't happen in practice (GH API only returns advisories matching
    // our package query), but the fallback preserves prior single-entry behaviour.
    const gh = [buildSequelizeStyleGhsa()]
    const merged = mergeAdvisories([], gh, '6.5.0', 'unrelated-pkg')
    // Falls back to vulnerabilities[0] = @sequelize/core, range matches 6.5.0
    assert.strictEqual(merged.length, 1)
    assert.strictEqual(merged[0].vulnerable_versions, '< 7.0.0-alpha.20')
  })
})
