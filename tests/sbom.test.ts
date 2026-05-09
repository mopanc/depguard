import { describe, it, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSBOM, makePurl, parseIntegrity } from '../src/sbom.js'

const tmpRoots: string[] = []

function makeProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-sbom-'))
  tmpRoots.push(dir)
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

after(() => {
  for (const dir of tmpRoots) {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
})

describe('makePurl', () => {
  it('encodes unscoped npm packages', () => {
    assert.strictEqual(makePurl('lodash', '4.17.21'), 'pkg:npm/lodash@4.17.21')
  })

  it('encodes scoped npm packages with %40', () => {
    assert.strictEqual(
      makePurl('@types/node', '20.0.0'),
      'pkg:npm/%40types/node@20.0.0',
    )
  })

  it('percent-encodes special chars in versions', () => {
    // + in build metadata gets encoded to %2B
    const purl = makePurl('foo', '1.0.0+build.5')
    assert.ok(purl.includes('%2B'))
  })

  it('handles malformed scoped name without slash by treating it as unscoped', () => {
    // Edge case: starts with @ but no slash — fall through to unscoped path
    assert.strictEqual(makePurl('@weird', '1.0.0'), 'pkg:npm/%40weird@1.0.0')
  })
})

describe('parseIntegrity', () => {
  it('parses sha512 integrity into hex', () => {
    // base64 of "test" = "dGVzdA==", but we want a sha512 hash.
    // Here: sha512 of empty string padded for test purposes.
    const b64 = Buffer.from('hello world').toString('base64')
    const result = parseIntegrity(`sha512-${b64}`)
    assert.ok(result)
    assert.strictEqual(result?.alg, 'SHA-512')
    assert.strictEqual(result?.content, Buffer.from('hello world').toString('hex'))
  })

  it('prefers stronger algorithm when multiple are present', () => {
    const sha1 = `sha1-${Buffer.from('a').toString('base64')}`
    const sha512 = `sha512-${Buffer.from('b').toString('base64')}`
    const result = parseIntegrity(`${sha1} ${sha512}`)
    assert.strictEqual(result?.alg, 'SHA-512')
    assert.strictEqual(result?.content, Buffer.from('b').toString('hex'))
  })

  it('returns null for unknown algorithm', () => {
    assert.strictEqual(parseIntegrity('rot13-XYZ'), null)
  })

  it('returns null for malformed integrity', () => {
    assert.strictEqual(parseIntegrity('not-an-integrity'), null)
  })
})

describe('generateSBOM', () => {
  let projectPath: string
  let pkgJson: string

  beforeEach(() => {
    projectPath = makeProject({
      'package.json': JSON.stringify({
        name: 'demo-app',
        version: '1.2.3',
        description: 'A demo project for SBOM tests',
        license: 'MIT',
        dependencies: { lodash: '^4.17.21' },
        devDependencies: { typescript: '^5.0.0' },
      }),
      'package-lock.json': JSON.stringify({
        name: 'demo-app',
        version: '1.2.3',
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo-app', version: '1.2.3' },
          'node_modules/lodash': {
            version: '4.17.21',
            integrity: `sha512-${Buffer.from('lodashhash').toString('base64')}`,
          },
          'node_modules/typescript': {
            version: '5.0.0',
            integrity: `sha512-${Buffer.from('tshash').toString('base64')}`,
            dev: true,
          },
        },
      }),
    })
    pkgJson = join(projectPath, 'package.json')
  })

  it('produces a CycloneDX 1.6 BOM with correct envelope', async () => {
    const bom = await generateSBOM(pkgJson, {
      timestamp: '2026-04-25T12:00:00.000Z',
      serialNumber: 'urn:uuid:00000000-0000-0000-0000-000000000000',
    })

    assert.strictEqual(bom.bomFormat, 'CycloneDX')
    assert.strictEqual(bom.specVersion, '1.6')
    assert.strictEqual(bom.version, 1)
    assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]+$/i)
    assert.strictEqual(bom.metadata?.timestamp, '2026-04-25T12:00:00.000Z')
  })

  it('includes a metadata.component for the project itself', async () => {
    const bom = await generateSBOM(pkgJson)
    const root = bom.metadata?.component
    assert.ok(root)
    assert.strictEqual(root?.name, 'demo-app')
    assert.strictEqual(root?.version, '1.2.3')
    assert.strictEqual(root?.type, 'application')
    assert.strictEqual(root?.purl, 'pkg:npm/demo-app@1.2.3')
    assert.strictEqual(root?.description, 'A demo project for SBOM tests')
    assert.deepStrictEqual(root?.licenses, [{ license: { id: 'MIT' } }])
  })

  it('lists library components from the lock file with PURLs', async () => {
    const bom = await generateSBOM(pkgJson)
    const lodash = bom.components?.find(c => c.name === 'lodash')
    assert.ok(lodash, 'lodash component should be present')
    assert.strictEqual(lodash?.type, 'library')
    assert.strictEqual(lodash?.scope, 'required')
    assert.strictEqual(lodash?.version, '4.17.21')
    assert.strictEqual(lodash?.purl, 'pkg:npm/lodash@4.17.21')
    assert.strictEqual(lodash?.['bom-ref'], 'pkg:npm/lodash@4.17.21')
  })

  it('attaches integrity hashes to components when available', async () => {
    const bom = await generateSBOM(pkgJson)
    const lodash = bom.components?.find(c => c.name === 'lodash')
    assert.ok(lodash?.hashes && lodash.hashes.length > 0)
    assert.strictEqual(lodash?.hashes?.[0].alg, 'SHA-512')
    assert.strictEqual(
      lodash?.hashes?.[0].content,
      Buffer.from('lodashhash').toString('hex'),
    )
  })

  it('does not duplicate the root project as a library component', async () => {
    const bom = await generateSBOM(pkgJson)
    const matches = bom.components?.filter(c => c.name === 'demo-app') ?? []
    assert.strictEqual(matches.length, 0)
  })

  it('encodes the dependency graph from root → direct deps only by default', async () => {
    const bom = await generateSBOM(pkgJson)
    assert.ok(bom.dependencies)
    assert.strictEqual(bom.dependencies?.length, 1)
    const root = bom.dependencies?.[0]
    assert.strictEqual(root?.ref, 'pkg:npm/demo-app@1.2.3')
    assert.deepStrictEqual(root?.dependsOn, ['pkg:npm/lodash@4.17.21'])
  })

  it('includes devDependencies when includeDevDependencies is set', async () => {
    const bom = await generateSBOM(pkgJson, { includeDevDependencies: true })
    const root = bom.dependencies?.[0]
    assert.ok(root?.dependsOn?.includes('pkg:npm/typescript@5.0.0'))
  })

  it('records depguard as the producing tool', async () => {
    const bom = await generateSBOM(pkgJson)
    const tool = bom.metadata?.tools?.components?.[0]
    assert.strictEqual(tool?.name, 'depguard')
    assert.match(tool?.version ?? '', /^\d+\.\d+\.\d+$/)
    assert.strictEqual(tool?.publisher, 'Jorge Morais')
  })

  it('omits the vulnerabilities section when includeVex is false', async () => {
    const bom = await generateSBOM(pkgJson)
    assert.strictEqual(bom.vulnerabilities, undefined)
  })

  it('throws when package.json does not exist', async () => {
    await assert.rejects(
      () => generateSBOM('/this/path/does/not/exist/package.json'),
      /package\.json not found/,
    )
  })

  it('throws on malformed package.json', async () => {
    const dir = makeProject({ 'package.json': '{ this is not valid json' })
    await assert.rejects(
      () => generateSBOM(join(dir, 'package.json')),
      /Failed to parse package\.json/,
    )
  })

  it('falls back to directory basename when name is missing', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ version: '0.0.0' }),
    })
    const bom = await generateSBOM(join(dir, 'package.json'))
    const root = bom.metadata?.component
    assert.ok(root?.name)
    if (root?.name) {
      assert.strictEqual(root.purl, makePurl(root.name, '0.0.0'))
    }
  })

  it('uses default version 0.0.0 when version is missing', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'no-version-pkg' }),
    })
    const bom = await generateSBOM(join(dir, 'package.json'))
    assert.strictEqual(bom.metadata?.component?.version, '0.0.0')
  })

  it('handles a project with no lock file (no transitive components)', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({
        name: 'lockless',
        version: '0.1.0',
        dependencies: { lodash: '^4.0.0' },
      }),
    })
    const bom = await generateSBOM(join(dir, 'package.json'))
    assert.strictEqual(bom.components?.length, 0)
    assert.deepStrictEqual(bom.dependencies?.[0].dependsOn, [])
  })

  it('produces output that round-trips through JSON serialization', async () => {
    const bom = await generateSBOM(pkgJson)
    const json = JSON.stringify(bom)
    const parsed = JSON.parse(json)
    assert.strictEqual(parsed.bomFormat, 'CycloneDX')
    assert.strictEqual(parsed.specVersion, '1.6')
  })

  // ─── per-component licenses (#63) ──────────────────────────────────────

  it('reads license from node_modules/<pkg>/package.json for each component (#63)', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({
        name: 'app',
        version: '1.0.0',
        dependencies: { axios: '^1.0.0' },
      }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', version: '1.0.0' },
          'node_modules/axios': { version: '1.14.0' },
        },
      }),
      'node_modules/axios/package.json': JSON.stringify({
        name: 'axios',
        version: '1.14.0',
        license: 'MIT',
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const axios = bom.components?.find(c => c.name === 'axios')
    assert.deepStrictEqual(axios?.licenses, [{ license: { id: 'MIT' } }])
  })

  it('emits SPDX expression for compound licenses like "MIT OR Apache-2.0"', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { 'pkg-a': '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/pkg-a': { version: '1.0.0' },
        },
      }),
      'node_modules/pkg-a/package.json': JSON.stringify({
        name: 'pkg-a',
        version: '1.0.0',
        license: 'MIT OR Apache-2.0',
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'pkg-a')
    assert.deepStrictEqual(pkg?.licenses, [{ expression: 'MIT OR Apache-2.0' }])
  })

  it('handles legacy license object form { type, url }', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { 'old-pkg': '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/old-pkg': { version: '1.0.0' },
        },
      }),
      'node_modules/old-pkg/package.json': JSON.stringify({
        name: 'old-pkg',
        version: '1.0.0',
        license: { type: 'ISC', url: 'https://opensource.org/licenses/ISC' },
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'old-pkg')
    assert.deepStrictEqual(pkg?.licenses, [{ license: { id: 'ISC' } }])
  })

  it('handles legacy licenses array form [{ type, url }, ...]', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { 'multi-lic': '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/multi-lic': { version: '1.0.0' },
        },
      }),
      'node_modules/multi-lic/package.json': JSON.stringify({
        name: 'multi-lic',
        version: '1.0.0',
        licenses: [
          { type: 'MIT', url: 'https://opensource.org/licenses/MIT' },
          { type: 'BSD-3-Clause', url: 'https://opensource.org/licenses/BSD-3-Clause' },
        ],
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'multi-lic')
    assert.deepStrictEqual(pkg?.licenses, [
      { license: { id: 'MIT' } },
      { license: { id: 'BSD-3-Clause' } },
    ])
  })

  it('falls back to explicit UNKNOWN when no license metadata can be found', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { 'no-lic': '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/no-lic': { version: '1.0.0' },
        },
      }),
      'node_modules/no-lic/package.json': JSON.stringify({
        name: 'no-lic',
        version: '1.0.0',
        // no license, no licenses
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'no-lic')
    assert.deepStrictEqual(pkg?.licenses, [{ license: { name: 'UNKNOWN' } }])
  })

  it('uses license.name for non-SPDX strings like "SEE LICENSE IN LICENSE.txt"', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { 'custom-lic': '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/custom-lic': { version: '1.0.0' },
        },
      }),
      'node_modules/custom-lic/package.json': JSON.stringify({
        name: 'custom-lic',
        version: '1.0.0',
        license: 'SEE LICENSE IN LICENSE.txt',
      }),
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'custom-lic')
    assert.deepStrictEqual(pkg?.licenses, [{ license: { name: 'SEE LICENSE IN LICENSE.txt' } }])
  })

  it('falls back to UNKNOWN when node_modules/<pkg> is not installed', async () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', dependencies: { ghost: '^1' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/ghost': { version: '1.0.0' },
        },
      }),
      // No node_modules/ghost on disk
    })

    const bom = await generateSBOM(join(dir, 'package.json'))
    const pkg = bom.components?.find(c => c.name === 'ghost')
    assert.deepStrictEqual(pkg?.licenses, [{ license: { name: 'UNKNOWN' } }])
  })
})
