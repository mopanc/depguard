import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scanExposure, parseTarballUrl, readNpmCacheTarballs, walkNodeModules } from '../src/exposure.js'
import { parseLockfilePackages } from '../src/lockfile.js'

// Curated, hand-verified incidents in src/data/advisory-db.json:
//   event-stream 3.3.6, ua-parser-js 0.7.29 / 0.8.0 / 1.0.0

function withDir(body: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-exposure-'))
  try {
    body(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function write(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true })
  writeFileSync(path, content)
}

function npmLock(packages: Record<string, Record<string, unknown>>): string {
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages: { '': { name: 'app' }, ...packages } })
}

/** Scan only the fixture: no real global packages, no real npm cache. */
function scan(dir: string, extra: Parameters<typeof scanExposure>[0] = {}) {
  return scanExposure({ roots: [dir], includeGlobal: false, includeCache: false, ...extra })
}

describe('scanExposure — lock files', () => {
  it('reports a known-malicious version with its lock file and install path', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'package-lock.json'), npmLock({
        'node_modules/event-stream': { version: '3.3.6' },
      }))
      const r = scan(dir)
      assert.equal(r.exposed, true)
      assert.equal(r.findings.length, 1)
      const f = r.findings[0]
      assert.equal(f.name, 'event-stream')
      assert.equal(f.version, '3.3.6')
      assert.equal(f.locations[0].kind, 'lockfile')
      assert.equal(f.locations[0].path, join(dir, 'proj', 'package-lock.json'))
      assert.equal(f.locations[0].installPath, 'node_modules/event-stream')
      assert.ok(r.nextSteps.length > 0)
    })
  })

  it('finds a malicious copy nested under another package', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'package-lock.json'), npmLock({
        'node_modules/event-stream': { version: '4.0.1' },
        'node_modules/flatmap-stream-user/node_modules/event-stream': { version: '3.3.6' },
      }))
      const r = scan(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].locations[0].installPath, 'node_modules/flatmap-stream-user/node_modules/event-stream')
    })
  })

  it('does NOT flag clean versions of historically compromised packages (FP policy rule 7)', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'package-lock.json'), npmLock({
        'node_modules/ua-parser-js': { version: '1.0.39' },
        'node_modules/event-stream': { version: '4.0.1' },
      }))
      const r = scan(dir)
      assert.equal(r.exposed, false)
      assert.deepEqual(r.findings, [])
      assert.deepEqual(r.nextSteps, [])
    })
  })

  it('marks onDisk true only when that exact version is installed', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'package-lock.json'), npmLock({
        'node_modules/ua-parser-js': { version: '0.7.29', hasInstallScript: true },
      }))
      const before = scan(dir).findings[0].locations[0]
      assert.equal(before.onDisk, false)
      assert.equal(before.hasInstallScript, true)

      write(join(dir, 'proj', 'node_modules', 'ua-parser-js', 'package.json'), JSON.stringify({ name: 'ua-parser-js', version: '0.7.29' }))
      assert.equal(scan(dir).findings[0].locations[0].onDisk, true)
    })
  })

  it('does not tell the user to treat the machine as compromised when the version never reached disk', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'package-lock.json'), npmLock({ 'node_modules/event-stream': { version: '3.3.6' } }))
      const lockOnly = scan(dir).nextSteps.join(' ')
      assert.ok(lockOnly.includes('does not appear to have run'))
      assert.ok(!lockOnly.includes('Treat the machine as compromised'))

      write(join(dir, 'proj', 'node_modules', 'event-stream', 'package.json'), JSON.stringify({ name: 'event-stream', version: '3.3.6' }))
      const installed = scan(dir).nextSteps.join(' ')
      assert.ok(installed.includes('Treat the machine as compromised'))
      assert.ok(installed.includes('Rotate every credential'))
    })
  })

  it('assumes compromise when the layout cannot prove the version is absent (yarn/pnpm)', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'yarn.lock'), '# yarn lockfile v1\n\nevent-stream@3.3.6:\n  version "3.3.6"\n')
      const steps = scan(dir).nextSteps.join(' ')
      assert.ok(steps.includes('could not be confirmed absent'))
      assert.ok(steps.includes('Rotate every credential'))
    })
  })

  it('does not treat lock files inside node_modules as projects', () => {
    withDir(dir => {
      write(join(dir, 'proj', 'node_modules', 'some-dep', 'package-lock.json'), npmLock({
        'node_modules/event-stream': { version: '3.3.6' },
      }))
      const r = scan(dir)
      assert.equal(r.stats.lockfiles, 0)
      assert.equal(r.exposed, false)
    })
  })

  it('aggregates every location of the same malicious version', () => {
    withDir(dir => {
      write(join(dir, 'a', 'package-lock.json'), npmLock({ 'node_modules/event-stream': { version: '3.3.6' } }))
      write(join(dir, 'b', 'yarn.lock'), '# yarn lockfile v1\n\nevent-stream@3.3.6:\n  version "3.3.6"\n')
      const r = scan(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].locations.length, 2)
    })
  })

  it('respects maxDepth', () => {
    withDir(dir => {
      write(join(dir, 'a', 'b', 'c', 'package-lock.json'), npmLock({ 'node_modules/event-stream': { version: '3.3.6' } }))
      assert.equal(scan(dir, { maxDepth: 2 }).stats.lockfiles, 0)
      assert.equal(scan(dir, { maxDepth: 3 }).stats.lockfiles, 1)
    })
  })
})

describe('scanExposure — global packages', () => {
  it('finds malicious versions in a global node_modules tree, nested included', () => {
    withDir(dir => {
      const root = join(dir, 'global', 'node_modules')
      write(join(root, 'some-cli', 'package.json'), JSON.stringify({ name: 'some-cli', version: '1.0.0' }))
      write(join(root, 'some-cli', 'node_modules', 'event-stream', 'package.json'), JSON.stringify({ name: 'event-stream', version: '3.3.6' }))
      write(join(root, '@scope', 'tool', 'package.json'), JSON.stringify({ name: '@scope/tool', version: '2.0.0' }))
      const r = scanExposure({ roots: [join(dir, 'empty')], includeCache: false, globalRoots: [root] })
      assert.equal(r.stats.globalPackages, 3)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].locations[0].kind, 'global')
      assert.equal(r.findings[0].locations[0].onDisk, true)
    })
  })

  it('walkNodeModules lists scoped and nested packages', () => {
    withDir(dir => {
      write(join(dir, 'a', 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0' }))
      write(join(dir, '@s', 'b', 'package.json'), JSON.stringify({ name: '@s/b', version: '2.0.0' }))
      write(join(dir, 'a', 'node_modules', 'c', 'package.json'), JSON.stringify({ name: 'c', version: '3.0.0' }))
      const names = walkNodeModules(dir).map(p => `${p.name}@${p.version}`).sort()
      assert.deepEqual(names, ['@s/b@2.0.0', 'a@1.0.0', 'c@3.0.0'])
    })
  })
})

describe('scanExposure — npm cache', () => {
  function cacheLine(url: string, time: number): string {
    return `0123abcd\t${JSON.stringify({ key: `make-fetch-happen:request-cache:${url}`, integrity: 'sha512-x', time, size: 1 })}\n`
  }

  it('reports a malicious tarball downloaded on this machine, with the date', () => {
    withDir(dir => {
      const time = Date.UTC(2021, 9, 22)
      write(join(dir, '_cacache', 'index-v5', 'ab', 'cd', 'entry'),
        cacheLine('https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz', time) +
        cacheLine('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', time))
      const r = scanExposure({ roots: [join(dir, 'empty')], includeGlobal: false, cacheDir: dir })
      assert.equal(r.stats.cacheEntries, 2)
      assert.equal(r.findings.length, 1)
      const loc = r.findings[0].locations[0]
      assert.equal(loc.kind, 'npm-cache')
      assert.equal(loc.downloadedAt, new Date(time).toISOString())
    })
  })

  it('ignores metadata entries and malformed lines', () => {
    withDir(dir => {
      write(join(dir, '_cacache', 'index-v5', 'ab', 'entry'),
        `abc\t${JSON.stringify({ key: 'make-fetch-happen:request-cache:https://registry.npmjs.org/event-stream', time: 1 })}\n` +
        'not a cache line\n' +
        'abc\t{broken json\n')
      assert.deepEqual(readNpmCacheTarballs(dir), [])
    })
  })

  it('returns nothing when the cache directory does not exist', () => {
    assert.deepEqual(readNpmCacheTarballs(join(tmpdir(), 'depguard-no-such-cache')), [])
  })
})

describe('parseTarballUrl', () => {
  it('parses unscoped, scoped, encoded-scope and path-prefixed registry URLs', () => {
    assert.deepEqual(parseTarballUrl('https://registry.npmjs.org/debug/-/debug-4.4.2.tgz'), { name: 'debug', version: '4.4.2' })
    assert.deepEqual(parseTarballUrl('https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz'), { name: '@ctrl/tinycolor', version: '4.1.1' })
    assert.deepEqual(parseTarballUrl('https://registry.npmjs.org/@ctrl%2ftinycolor/-/tinycolor-4.1.1.tgz'), { name: '@ctrl/tinycolor', version: '4.1.1' })
    assert.deepEqual(parseTarballUrl('https://art.example/api/npm/remote/debug/-/debug-4.4.2.tgz'), { name: 'debug', version: '4.4.2' })
  })

  it('returns null for non-tarball or non-registry URLs', () => {
    assert.equal(parseTarballUrl('https://registry.npmjs.org/debug'), null)
    assert.equal(parseTarballUrl('https://codeload.github.com/a/b/tar.gz/main'), null)
    assert.equal(parseTarballUrl('not a url'), null)
  })
})

describe('parseLockfilePackages', () => {
  it('npm v3: keeps nested and duplicate copies, resolves aliases, skips links and workspaces', () => {
    withDir(dir => {
      const lock = join(dir, 'package-lock.json')
      write(lock, npmLock({
        'node_modules/a': { version: '1.0.0' },
        'node_modules/b/node_modules/a': { version: '2.0.0', hasInstallScript: true },
        'node_modules/alias': { name: 'real-pkg', version: '3.0.0' },
        'node_modules/ws-link': { resolved: 'packages/x', link: true },
        'packages/x': { name: 'x', version: '0.0.1' },
      }))
      const pkgs = parseLockfilePackages(lock).map(p => `${p.name}@${p.version}`).sort()
      assert.deepEqual(pkgs, ['a@1.0.0', 'a@2.0.0', 'real-pkg@3.0.0'])
      assert.equal(parseLockfilePackages(lock).find(p => p.version === '2.0.0')?.hasInstallScript, true)
    })
  })

  it('npm v1: walks nested dependencies and npm: aliases', () => {
    withDir(dir => {
      const lock = join(dir, 'package-lock.json')
      write(lock, JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          a: { version: '1.0.0', dependencies: { c: { version: '0.1.0' } } },
          b: { version: 'npm:real-b@2.0.0' },
        },
      }))
      const pkgs = parseLockfilePackages(lock).map(p => `${p.name}@${p.version}@${p.path}`).sort()
      assert.deepEqual(pkgs, [
        'a@1.0.0@node_modules/a',
        'c@0.1.0@node_modules/a/node_modules/c',
        'real-b@2.0.0@node_modules/b',
      ])
    })
  })

  it('pnpm v9: reads packages and snapshots, strips peer suffixes, skips non-registry specs', () => {
    withDir(dir => {
      const lock = join(dir, 'pnpm-lock.yaml')
      write(lock, `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react-dom:
        specifier: ^18.0.0
        version: 18.2.0(react@18.2.0)

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}

  react-dom@18.2.0:
    resolution: {integrity: sha512-y}

snapshots:

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  local-pkg@link:../local: {}
`)
      const pkgs = parseLockfilePackages(lock).map(p => `${p.name}@${p.version}`).sort()
      assert.deepEqual(pkgs, ['@babel/core@7.24.0', 'react-dom@18.2.0'])
    })
  })

  it('pnpm v6: handles leading-slash keys', () => {
    withDir(dir => {
      const lock = join(dir, 'pnpm-lock.yaml')
      write(lock, `lockfileVersion: '6.0'

packages:

  /debug@4.3.4:
    resolution: {integrity: sha512-x}

  /@types/node@20.0.0:
    resolution: {integrity: sha512-y}
`)
      const pkgs = parseLockfilePackages(lock).map(p => `${p.name}@${p.version}`).sort()
      assert.deepEqual(pkgs, ['@types/node@20.0.0', 'debug@4.3.4'])
    })
  })

  it('bun: derives names from the resolved spec', () => {
    withDir(dir => {
      const lock = join(dir, 'bun.lock')
      write(lock, `{
  // bun lockfile
  "lockfileVersion": 1,
  "packages": {
    "debug": ["debug@4.3.4", "", {}, "sha512-x"],
    "@types/node": ["@types/node@20.0.0", "", {}, "sha512-y"],
    "local": ["local@workspace:packages/local"],
  }
}`)
      const pkgs = parseLockfilePackages(lock).map(p => `${p.name}@${p.version}`).sort()
      assert.deepEqual(pkgs, ['@types/node@20.0.0', 'debug@4.3.4'])
    })
  })

  it('returns [] for unknown or malformed files', () => {
    withDir(dir => {
      write(join(dir, 'package-lock.json'), '{ not json')
      assert.deepEqual(parseLockfilePackages(join(dir, 'package-lock.json')), [])
      assert.deepEqual(parseLockfilePackages(join(dir, 'Cargo.lock')), [])
    })
  })
})
