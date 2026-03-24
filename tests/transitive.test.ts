import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { auditTransitive } from '../src/transitive.js'
import { clearCache, disableDiskCache } from '../src/registry.js'
import type { FetchFn } from '../src/types.js'

/**
 * Create a mock fetch that serves multiple packages with their dependencies.
 * packages: { name: { deps: { depName: version }, advisories?: [...] } }
 */
function createTreeFetch(
  packages: Record<string, { deps?: Record<string, string>; deprecated?: boolean; license?: string }>,
  advisories: Record<string, unknown[]> = {},
): FetchFn {
  return ((input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    // Package metadata
    for (const [name, data] of Object.entries(packages)) {
      if (url.includes(`registry.npmjs.org/${encodeURIComponent(name)}`)) {
        const pkg = {
          name,
          description: `Mock ${name}`,
          'dist-tags': { latest: '1.0.0' },
          license: data.license ?? 'MIT',
          time: { created: '2024-01-01T00:00:00.000Z', '1.0.0': '2024-01-01T00:00:00.000Z' },
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              license: data.license ?? 'MIT',
              dependencies: data.deps ?? {},
              deprecated: data.deprecated ? 'Use something else' : undefined,
            },
          },
          maintainers: [{ name: 'dev' }],
        }
        return Promise.resolve({ ok: true, json: async () => pkg } as Response)
      }
    }

    // Advisories bulk endpoint
    if (url.includes('security/advisories/bulk')) {
      return Promise.resolve({ ok: true, json: async () => advisories } as Response)
    }

    // Downloads
    if (url.includes('api.npmjs.org/downloads')) {
      return Promise.resolve({ ok: true, json: async () => ({ downloads: 1000 }) } as Response)
    }

    // GitHub advisories (empty by default)
    if (url.includes('api.github.com')) {
      return Promise.resolve({ ok: true, json: async () => [] } as Response)
    }

    return Promise.resolve({ ok: false, status: 404 } as Response)
  }) as FetchFn
}

beforeEach(() => {
  clearCache(); disableDiskCache()
})

describe('auditTransitive', () => {
  it('builds a basic tree with direct and transitive deps', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'dep-a': '^1.0.0', 'dep-b': '^1.0.0' } },
      'dep-a': { deps: { 'dep-c': '^1.0.0' } },
      'dep-b': { deps: {} },
      'dep-c': { deps: {} },
    })

    const result = await auditTransitive('root-pkg', { fetcher })
    assert.strictEqual(result.root, 'root-pkg')
    assert.strictEqual(result.totalTransitiveDeps, 3) // dep-a, dep-b, dep-c
    assert.ok(result.nodes.some(n => n.name === 'dep-a' && n.depth === 1))
    assert.ok(result.nodes.some(n => n.name === 'dep-c' && n.depth === 2))
  })

  it('detects circular dependencies', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'dep-a': '^1.0.0' } },
      'dep-a': { deps: { 'dep-b': '^1.0.0' } },
      'dep-b': { deps: { 'dep-a': '^1.0.0' } }, // circular: dep-b -> dep-a
    })

    const result = await auditTransitive('root-pkg', { fetcher })
    assert.ok(result.circularDeps.length > 0)
    assert.ok(result.nodes.some(n => n.circular === true))
  })

  it('respects maxDepth limit', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'dep-a': '^1.0.0' } },
      'dep-a': { deps: { 'dep-b': '^1.0.0' } },
      'dep-b': { deps: { 'dep-c': '^1.0.0' } },
      'dep-c': { deps: { 'dep-d': '^1.0.0' } },
      'dep-d': { deps: {} },
    })

    const result = await auditTransitive('root-pkg', { fetcher, maxDepth: 2 })
    assert.strictEqual(result.maxDepthLimit, 2)
    // Should only have dep-a (depth 1) and dep-b (depth 2)
    assert.ok(result.nodes.every(n => n.depth <= 2))
    assert.ok(!result.nodes.some(n => n.name === 'dep-c'))
  })

  it('aggregates vulnerabilities across tree', async () => {
    const fetcher = createTreeFetch(
      {
        'root-pkg': { deps: { 'vuln-dep': '^1.0.0' } },
        'vuln-dep': { deps: {} },
      },
      {
        'vuln-dep': [{
          id: 1, title: 'XSS', severity: 'high',
          url: 'https://example.com', vulnerable_versions: '*', patched_versions: null,
        }],
      },
    )

    const result = await auditTransitive('root-pkg', { fetcher })
    assert.strictEqual(result.aggregateVulnerabilities.total, 1)
    assert.strictEqual(result.aggregateVulnerabilities.high, 1)
    assert.ok(result.aggregateVulnerabilities.byPackage.some(p => p.name === 'vuln-dep'))
  })

  it('handles network error on transitive dep gracefully', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'good-dep': '^1.0.0', 'bad-dep': '^1.0.0' } },
      'good-dep': { deps: {} },
      // 'bad-dep' not in mock → will return 404
    })

    const result = await auditTransitive('root-pkg', { fetcher })
    assert.ok(result.nodes.some(n => n.name === 'good-dep'))
    assert.ok(result.nodes.some(n => n.name === 'bad-dep' && n.version === 'unknown'))
  })

  it('returns empty tree for package with no deps', async () => {
    const fetcher = createTreeFetch({ 'lonely-pkg': { deps: {} } })
    const result = await auditTransitive('lonely-pkg', { fetcher })
    assert.strictEqual(result.totalTransitiveDeps, 0)
    assert.strictEqual(result.nodes.length, 0)
  })

  it('returns degraded result when root package not found', async () => {
    const fetcher = (() => Promise.resolve({ ok: false, status: 404 } as Response)) as FetchFn
    const result = await auditTransitive('nonexistent', { fetcher })
    assert.strictEqual(result.rootVersion, 'unknown')
    assert.ok(result.warnings.some(w => w.includes('Could not fetch root')))
  })

  it('handles diamond dependency (A->B, A->C, B->D, C->D)', async () => {
    const fetcher = createTreeFetch({
      'root': { deps: { 'b': '^1.0.0', 'c': '^1.0.0' } },
      'b': { deps: { 'd': '^1.0.0' } },
      'c': { deps: { 'd': '^1.0.0' } },
      'd': { deps: {} },
    })

    const result = await auditTransitive('root', { fetcher })
    // 'd' should appear once with 2 requiredBy entries
    const dNode = result.nodes.find(n => n.name === 'd')
    assert.ok(dNode)
    assert.strictEqual(result.uniquePackages, 3) // b, c, d
  })

  it('captures license from transitive deps', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'gpl-dep': '^1.0.0' } },
      'gpl-dep': { deps: {}, license: 'GPL-3.0' },
    })

    const result = await auditTransitive('root-pkg', { fetcher })
    const gplNode = result.nodes.find(n => n.name === 'gpl-dep')
    assert.strictEqual(gplNode?.license, 'GPL-3.0')
  })

  it('captures deprecated flag on transitive deps', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'old-dep': '^1.0.0' } },
      'old-dep': { deps: {}, deprecated: true },
    })

    const result = await auditTransitive('root-pkg', { fetcher })
    const oldNode = result.nodes.find(n => n.name === 'old-dep')
    assert.strictEqual(oldNode?.deprecated, true)
  })

  it('maxDepth=1 only returns direct deps', async () => {
    const fetcher = createTreeFetch({
      'root-pkg': { deps: { 'dep-a': '^1.0.0' } },
      'dep-a': { deps: { 'dep-b': '^1.0.0' } },
      'dep-b': { deps: {} },
    })

    const result = await auditTransitive('root-pkg', { fetcher, maxDepth: 1 })
    assert.strictEqual(result.nodes.length, 1)
    assert.strictEqual(result.nodes[0].name, 'dep-a')
  })

  it('uses default options when not specified', async () => {
    const fetcher = createTreeFetch({ 'root-pkg': { deps: {} } })
    const result = await auditTransitive('root-pkg', { fetcher })
    assert.strictEqual(result.maxDepthLimit, 5) // default
  })

  it('handles large tree without timeout', async () => {
    // Create a wide tree: root -> 20 direct deps, each with 2 children
    const packages: Record<string, { deps: Record<string, string> }> = {
      'root-pkg': { deps: {} },
    }
    for (let i = 0; i < 20; i++) {
      const depName = `dep-${i}`
      packages['root-pkg'].deps[depName] = '^1.0.0'
      packages[depName] = { deps: { [`sub-${i}-a`]: '^1.0.0', [`sub-${i}-b`]: '^1.0.0' } }
      packages[`sub-${i}-a`] = { deps: {} }
      packages[`sub-${i}-b`] = { deps: {} }
    }

    const fetcher = createTreeFetch(packages)
    const result = await auditTransitive('root-pkg', { fetcher })
    // 20 direct deps + their children (up to 40 sub-deps)
    assert.ok(result.totalTransitiveDeps >= 20, `Expected at least 20 deps, got ${result.totalTransitiveDeps}`)
    assert.ok(result.warnings.length === 0 || result.totalTransitiveDeps > 0, 'Should complete without fatal errors')
  })
})
