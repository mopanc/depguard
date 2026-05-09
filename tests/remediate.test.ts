import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { remediate } from '../src/remediate.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

disableDiskCache()

const __dirname = dirname(fileURLToPath(import.meta.url))
const tmpDir = join(__dirname, '.tmp-remediate-test')

function makePkg(name: string, opts: { vulnerable?: boolean } = {}) {
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
    _vulnerable: !!opts.vulnerable,
  }
}

function createFetch(packages: Record<string, unknown>, advisoryResponses: Record<string, unknown> = {}): FetchFn {
  const baseAdv = (name: string) => packages[`registry.npmjs.org/${name}`] && (packages[`registry.npmjs.org/${name}`] as { _vulnerable?: boolean })._vulnerable
    ? [{ id: 7777, title: `Direct vuln in ${name}`, severity: 'critical', url: `https://github.com/advisories/G-${name}`, vulnerable_versions: '<=1.0.0', patched_versions: '>=1.0.1' }]
    : []

  return ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    for (const [pattern, body] of Object.entries(packages)) {
      if (url.includes(pattern)) {
        return Promise.resolve({ ok: true, json: async () => body } as Response)
      }
    }

    if (url.includes('api.npmjs.org/downloads')) {
      return Promise.resolve({ ok: true, json: async () => ({ downloads: 50000 }) } as Response)
    }

    if (url.includes('security/advisories/bulk') && init?.body) {
      const body = JSON.parse(init.body as string) as Record<string, string[]>
      const result: Record<string, unknown[]> = {}
      for (const name of Object.keys(body)) {
        if (advisoryResponses[name]) {
          result[name] = [advisoryResponses[name]]
        } else {
          const adv = baseAdv(name)
          if (adv.length > 0) result[name] = adv
        }
      }
      return Promise.resolve({ ok: true, json: async () => result } as Response)
    }

    if (url.includes('api.github.com/advisories')) {
      return Promise.resolve({
        ok: true,
        json: async () => [],
        headers: { get: () => null },
      } as unknown as Response)
    }

    return Promise.resolve({ ok: false } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache()
  mkdirSync(tmpDir, { recursive: true })
})

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

describe('remediate', () => {
  it('groups a transitive vuln under the direct dep that pulls it in', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-a': '^1.0.0' } },
        'node_modules/pkg-a': {
          version: '1.0.0',
          dependencies: { 'vuln-leaf': '^2.0.0' },
        },
        'node_modules/vuln-leaf': { version: '2.3.0' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
    }, {
      'vuln-leaf': {
        id: 9001,
        title: 'High vuln in vuln-leaf',
        severity: 'high',
        url: 'https://github.com/advisories/G-vl',
        vulnerable_versions: '<=2.5.0',
        patched_versions: '>=2.6.0',
      },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.totalRemediations, 1)
    assert.strictEqual(report.remediations[0].directDep, 'pkg-a')
    assert.strictEqual(report.remediations[0].isDirectVulnerable, false)
    assert.strictEqual(report.remediations[0].transitives.length, 1)
    assert.strictEqual(report.remediations[0].transitives[0].name, 'vuln-leaf')
    assert.strictEqual(report.remediations[0].severityCounts.high, 1)
    assert.strictEqual(report.remediations[0].action, 'bump')
    assert.strictEqual(report.unattributed.length, 0)
  })

  it('sorts remediations by severity weight, descending', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-low': '^1.0.0', 'pkg-high': '^1.0.0', 'pkg-crit': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-low': '^1.0.0', 'pkg-high': '^1.0.0', 'pkg-crit': '^1.0.0' } },
        'node_modules/pkg-low': { version: '1.0.0', dependencies: { 'leaf-low': '^1.0.0' } },
        'node_modules/pkg-high': { version: '1.0.0', dependencies: { 'leaf-high': '^1.0.0' } },
        'node_modules/pkg-crit': { version: '1.0.0', dependencies: { 'leaf-crit': '^1.0.0' } },
        'node_modules/leaf-low': { version: '1.0.0' },
        'node_modules/leaf-high': { version: '1.0.0' },
        'node_modules/leaf-crit': { version: '1.0.0' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-low': makePkg('pkg-low'),
      'registry.npmjs.org/pkg-high': makePkg('pkg-high'),
      'registry.npmjs.org/pkg-crit': makePkg('pkg-crit'),
    }, {
      'leaf-low': { id: 1, title: 'low', severity: 'low', url: 'https://x/1', vulnerable_versions: '*', patched_versions: '>=2' },
      'leaf-high': { id: 2, title: 'high', severity: 'high', url: 'https://x/2', vulnerable_versions: '*', patched_versions: '>=2' },
      'leaf-crit': { id: 3, title: 'crit', severity: 'critical', url: 'https://x/3', vulnerable_versions: '*', patched_versions: '>=2' },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.totalRemediations, 3)
    assert.strictEqual(report.remediations[0].directDep, 'pkg-crit')
    assert.strictEqual(report.remediations[1].directDep, 'pkg-high')
    assert.strictEqual(report.remediations[2].directDep, 'pkg-low')
  })

  it('records a transitive shared by two direct deps under both', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0', 'pkg-b': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-a': '^1.0.0', 'pkg-b': '^1.0.0' } },
        'node_modules/pkg-a': { version: '1.0.0', dependencies: { 'shared-leaf': '^1.0.0' } },
        'node_modules/pkg-b': { version: '1.0.0', dependencies: { 'shared-leaf': '^1.0.0' } },
        'node_modules/shared-leaf': { version: '1.0.0' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
      'registry.npmjs.org/pkg-b': makePkg('pkg-b'),
    }, {
      'shared-leaf': { id: 42, title: 'high', severity: 'high', url: 'https://x/42', vulnerable_versions: '*', patched_versions: '>=2' },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.totalRemediations, 2)
    const targets = new Set(report.remediations.map(r => r.directDep))
    assert.ok(targets.has('pkg-a'))
    assert.ok(targets.has('pkg-b'))
    for (const r of report.remediations) {
      assert.strictEqual(r.transitives.length, 1)
      assert.strictEqual(r.transitives[0].name, 'shared-leaf')
    }
  })

  it('infers a fix exists when patched_versions is missing but vulnerable_versions has an upper bound', async () => {
    // Mirrors the real npm bulk advisory response, which omits
    // patched_versions and only returns vulnerable_versions like "<1.1.13".
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-a': '^1.0.0' } },
        'node_modules/pkg-a': { version: '1.0.0', dependencies: { 'bounded-leaf': '^1.0.0' } },
        'node_modules/bounded-leaf': { version: '1.1.10' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
    }, {
      'bounded-leaf': {
        id: 88,
        title: 'ReDoS in bounded-leaf',
        severity: 'moderate',
        url: 'https://x/88',
        vulnerable_versions: '<1.1.13',
        // patched_versions intentionally absent — matches real npm bulk payload
      },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })
    assert.strictEqual(report.remediations[0].action, 'bump')
  })

  it('marks action as no-fix-available when patched_versions is empty', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-a': '^1.0.0' } },
        'node_modules/pkg-a': { version: '1.0.0', dependencies: { 'unfixable-leaf': '^1.0.0' } },
        'node_modules/unfixable-leaf': { version: '1.0.0' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
    }, {
      'unfixable-leaf': {
        id: 99,
        title: 'no fix',
        severity: 'high',
        url: 'https://x/99',
        vulnerable_versions: '*',
        patched_versions: '',
      },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.remediations[0].action, 'no-fix-available')
  })

  it('returns empty remediations for a project with no vulnerabilities', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0' },
    }))
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'pkg-a': '^1.0.0' } },
        'node_modules/pkg-a': { version: '1.0.0' },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.totalRemediations, 0)
    assert.strictEqual(report.totalVulnerableTransitives, 0)
    assert.strictEqual(report.remediations.length, 0)
    assert.strictEqual(report.unattributed.length, 0)
  })

  it('puts transitive vulns with no resolved parent into unattributed', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
      name: 'app',
      license: 'MIT',
      dependencies: { 'pkg-a': '^1.0.0' },
    }))
    // v1 lockfile format → getDependencyParents returns empty map →
    // any transitive vuln has no resolvable parent and lands in unattributed.
    writeFileSync(join(tmpDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        'pkg-a': {
          version: '1.0.0',
          dependencies: {
            'orphan-leaf': { version: '1.0.0' },
          },
        },
      },
    }))

    const fetcher = createFetch({
      'registry.npmjs.org/pkg-a': makePkg('pkg-a'),
    }, {
      'orphan-leaf': { id: 5, title: 'high', severity: 'high', url: 'https://x/5', vulnerable_versions: '*', patched_versions: '>=2' },
    })

    const report = await remediate(join(tmpDir, 'package.json'), { fetcher })

    assert.strictEqual(report.totalRemediations, 0)
    assert.strictEqual(report.unattributed.length, 1)
    assert.strictEqual(report.unattributed[0].name, 'orphan-leaf')
  })
})
