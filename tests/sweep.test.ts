import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  extractImports,
  normalizeToPackageName,
  collectSourceFiles,
  findConfigDependencies,
  findScriptDependencies,
  detectPhantomDeps,
  sweep,
} from '../src/sweep.js'

let testDir: string

beforeEach(() => {
  testDir = join(tmpdir(), `depguard-sweep-test-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  mkdirSync(testDir, { recursive: true })
})

afterEach(() => {
  try {
    rmSync(testDir, { recursive: true, force: true })
  } catch { /* ok */ }
})

describe('normalizeToPackageName', () => {
  it('returns unscoped package name', () => {
    assert.strictEqual(normalizeToPackageName('lodash/get'), 'lodash')
    assert.strictEqual(normalizeToPackageName('lodash'), 'lodash')
  })

  it('returns scoped package name', () => {
    assert.strictEqual(normalizeToPackageName('@scope/pkg/sub/path'), '@scope/pkg')
    assert.strictEqual(normalizeToPackageName('@scope/pkg'), '@scope/pkg')
  })
})

describe('extractImports', () => {
  it('parses ES static imports', () => {
    const source = `
      import express from 'express'
      import { useState } from 'react'
      import 'lodash'
    `
    const imports = extractImports(source)
    assert.ok(imports.has('express'))
    assert.ok(imports.has('react'))
    assert.ok(imports.has('lodash'))
  })

  it('parses dynamic imports', () => {
    const source = `
      const mod = await import('chalk')
      import('fs-extra').then(fs => fs.copy())
    `
    const imports = extractImports(source)
    assert.ok(imports.has('chalk'))
    assert.ok(imports.has('fs-extra'))
  })

  it('parses CommonJS require', () => {
    const source = `
      const express = require('express')
      const { join } = require('path')
      const debug = require('debug')
    `
    const imports = extractImports(source)
    assert.ok(imports.has('express'))
    assert.ok(imports.has('debug'))
    // 'path' is a bare name but not node: prefixed — we include it, but it won't be in package.json
    assert.ok(imports.has('path'))
  })

  it('parses re-exports', () => {
    const source = `
      export { default } from 'react'
      export type { FC } from 'react'
    `
    const imports = extractImports(source)
    assert.ok(imports.has('react'))
  })

  it('handles scoped packages with subpaths', () => {
    const source = `
      import { something } from '@babel/core/lib/config'
      import preset from '@babel/preset-env'
    `
    const imports = extractImports(source)
    assert.ok(imports.has('@babel/core'))
    assert.ok(imports.has('@babel/preset-env'))
  })

  it('ignores relative imports', () => {
    const source = `
      import { helper } from './utils'
      import config from '../config'
      import local from './local/module'
    `
    const imports = extractImports(source)
    assert.strictEqual(imports.size, 0)
  })

  it('ignores node: built-in modules', () => {
    const source = `
      import { readFileSync } from 'node:fs'
      import path from 'node:path'
    `
    const imports = extractImports(source)
    assert.strictEqual(imports.size, 0)
  })

  it('parses require.resolve', () => {
    const source = `
      const prettierPath = require.resolve('prettier')
      const configPath = require.resolve('@babel/core/config')
    `
    const imports = extractImports(source)
    assert.ok(imports.has('prettier'))
    assert.ok(imports.has('@babel/core'))
  })
})

describe('collectSourceFiles', () => {
  it('finds source files recursively', () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), 'export {}')
    writeFileSync(join(testDir, 'src', 'util.js'), 'module.exports = {}')
    writeFileSync(join(testDir, 'README.md'), '# Hello')

    const files = collectSourceFiles(testDir)
    assert.strictEqual(files.length, 2)
    assert.ok(files.some(f => f.endsWith('index.ts')))
    assert.ok(files.some(f => f.endsWith('util.js')))
  })

  it('excludes node_modules', () => {
    mkdirSync(join(testDir, 'node_modules', 'pkg'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'pkg', 'index.js'), 'module.exports = {}')
    writeFileSync(join(testDir, 'app.ts'), 'export {}')

    const files = collectSourceFiles(testDir)
    assert.strictEqual(files.length, 1)
    assert.ok(files[0].endsWith('app.ts'))
  })
})

describe('findConfigDependencies', () => {
  it('detects eslint from eslint.config.js', () => {
    writeFileSync(join(testDir, 'eslint.config.js'), 'export default {}')
    const deps = findConfigDependencies(testDir)
    assert.ok(deps.has('eslint'))
    assert.strictEqual(deps.get('eslint'), 'config-referenced')
  })

  it('detects typescript from tsconfig.json', () => {
    writeFileSync(join(testDir, 'tsconfig.json'), '{}')
    const deps = findConfigDependencies(testDir)
    assert.ok(deps.has('typescript'))
  })

  it('detects jest from jest.config.js', () => {
    writeFileSync(join(testDir, 'jest.config.js'), 'module.exports = {}')
    const deps = findConfigDependencies(testDir)
    assert.ok(deps.has('jest'))
  })
})

describe('findScriptDependencies', () => {
  it('detects binaries referenced in scripts', () => {
    // Create a fake node_modules with a binary
    mkdirSync(join(testDir, 'node_modules', 'eslint'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'eslint', 'package.json'), JSON.stringify({
      name: 'eslint',
      bin: { eslint: './bin/eslint.js' },
    }))

    const scripts = { lint: 'eslint src/', test: 'jest' }
    const deps = findScriptDependencies(scripts, testDir)
    assert.ok(deps.has('eslint'))
    assert.strictEqual(deps.get('eslint'), 'npm-script')
  })
})

describe('sweep', () => {
  it('reports unused dependency', async () => {
    // Create project with a dep that is not imported
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'lodash': '^4.0.0', 'express': '^4.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)

    const result = await sweep(testDir)
    assert.strictEqual(result.totalDependencies, 2)
    assert.strictEqual(result.used, 1)
    // lodash is unscoped + no node_modules = maybe-unused (conservative)
    const allUnused = [...result.unused, ...result.maybeUnused]
    assert.ok(allUnused.some(d => d.name === 'lodash'))
    assert.ok(result.note.length > 0)
  })

  it('does not flag imported dependency as unused', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'express': '^4.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)

    const result = await sweep(testDir)
    assert.strictEqual(result.unused.length, 0)
    assert.strictEqual(result.used, 1)
  })

  it('handles @types/* packages linked to runtime deps', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'express': '^4.0.0' },
      devDependencies: { '@types/express': '^4.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)

    const result = await sweep(testDir, { includeDevDependencies: true })
    assert.strictEqual(result.unused.length, 0)
    // @types/express should be recognized as types-only
    assert.strictEqual(result.used, 2)
  })

  it('handles config-only dependencies', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      devDependencies: { 'eslint': '^8.0.0', 'typescript': '^5.0.0' },
    }))
    writeFileSync(join(testDir, 'eslint.config.js'), 'export default {}')
    writeFileSync(join(testDir, 'tsconfig.json'), '{}')
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), 'export const x = 1')

    const result = await sweep(testDir, { includeDevDependencies: true })
    assert.strictEqual(result.unused.length, 0)
    assert.strictEqual(result.used, 2)
  })

  it('returns empty result for project with no deps', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({ name: 'test' }))
    const result = await sweep(testDir)
    assert.strictEqual(result.totalDependencies, 0)
    assert.strictEqual(result.unused.length, 0)
  })

  it('warns when no package.json found', async () => {
    const emptyDir = join(testDir, 'empty')
    mkdirSync(emptyDir)
    const result = await sweep(emptyDir)
    assert.ok(result.warnings.some(w => w.includes('No package.json')))
  })

  it('includes devDependencies when option set', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'express': '^4.0.0' },
      devDependencies: { 'jest': '^29.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)

    const result = await sweep(testDir, { includeDevDependencies: true })
    assert.strictEqual(result.totalDependencies, 2)
  })

  it('marks untraced devDependency as maybe-unused', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      devDependencies: { 'some-tool': '^1.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), 'export const x = 1')

    const result = await sweep(testDir, { includeDevDependencies: true })
    assert.strictEqual(result.maybeUnused.length, 1)
    assert.strictEqual(result.maybeUnused[0].name, 'some-tool')
    assert.strictEqual(result.maybeUnused[0].status, 'maybe-unused')
  })

  it('detects peer dependencies as used', async () => {
    // Create project where react-dom has react as a peerDep
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'react': '^18.0.0', 'react-dom': '^18.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import ReactDOM from 'react-dom'`)

    // Simulate node_modules with peer dependency
    mkdirSync(join(testDir, 'node_modules', 'react-dom'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'react-dom', 'package.json'), JSON.stringify({
      name: 'react-dom',
      peerDependencies: { 'react': '^18.0.0' },
    }))
    mkdirSync(join(testDir, 'node_modules', 'react'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'react', 'package.json'), JSON.stringify({
      name: 'react',
    }))

    const result = await sweep(testDir)
    // react should be detected as used via peer-dep even though it's not directly imported
    assert.strictEqual(result.unused.length, 0)
    assert.strictEqual(result.used, 2)
  })

  it('detects require.resolve as usage', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'prettier': '^3.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `const p = require.resolve('prettier')`)

    const result = await sweep(testDir)
    assert.strictEqual(result.unused.length, 0)
    assert.strictEqual(result.used, 1)
  })

  it('detects workspace dependencies as used', async () => {
    // Create a monorepo-like structure
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      workspaces: ['packages/*'],
      dependencies: { 'shared-utils': '^1.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), 'export const x = 1')

    // Create a workspace that uses the root dependency
    mkdirSync(join(testDir, 'packages', 'app'), { recursive: true })
    writeFileSync(join(testDir, 'packages', 'app', 'package.json'), JSON.stringify({
      name: '@my/app',
      dependencies: { 'shared-utils': '^1.0.0' },
    }))

    const result = await sweep(testDir)
    // shared-utils is used by workspace, so should not be unused
    assert.strictEqual(result.unused.length, 0)
  })

  it('warns about monorepo and still works', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      workspaces: ['packages/*'],
      dependencies: { 'express': '^4.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)

    const result = await sweep(testDir)
    assert.ok(result.warnings.some(w => w.includes('Monorepo')))
    assert.strictEqual(result.used, 1)
  })
})

describe('detectPhantomDeps', () => {
  it('detects phantom dependency in node_modules', () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'express': '^4.0.0' },
    }))
    // Create express (declared) and lodash (phantom)
    mkdirSync(join(testDir, 'node_modules', 'express'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'express', 'package.json'), JSON.stringify({ name: 'express', version: '4.18.0' }))
    mkdirSync(join(testDir, 'node_modules', 'lodash'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'lodash', 'package.json'), JSON.stringify({ name: 'lodash', version: '4.17.21' }))

    const phantoms = detectPhantomDeps(testDir, ['express'])
    assert.strictEqual(phantoms.length, 1)
    assert.strictEqual(phantoms[0].name, 'lodash')
    assert.strictEqual(phantoms[0].version, '4.17.21')
  })

  it('detects scoped phantom package', () => {
    mkdirSync(join(testDir, 'node_modules', '@scope', 'pkg'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', '@scope', 'pkg', 'package.json'), JSON.stringify({ name: '@scope/pkg', version: '1.0.0' }))

    const phantoms = detectPhantomDeps(testDir, [])
    assert.ok(phantoms.some(p => p.name === '@scope/pkg'))
  })

  it('returns empty when all packages are declared', () => {
    mkdirSync(join(testDir, 'node_modules', 'express'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'express', 'package.json'), JSON.stringify({ name: 'express' }))

    const phantoms = detectPhantomDeps(testDir, ['express'])
    assert.strictEqual(phantoms.length, 0)
  })

  it('returns empty when node_modules does not exist', () => {
    const phantoms = detectPhantomDeps(join(testDir, 'nonexistent'), [])
    assert.strictEqual(phantoms.length, 0)
  })

  it('ignores dot-prefixed entries', () => {
    mkdirSync(join(testDir, 'node_modules', '.package-lock.json'), { recursive: true })
    mkdirSync(join(testDir, 'node_modules', '.cache'), { recursive: true })

    const phantoms = detectPhantomDeps(testDir, [])
    assert.strictEqual(phantoms.length, 0)
  })

  it('is integrated into sweep results', async () => {
    writeFileSync(join(testDir, 'package.json'), JSON.stringify({
      dependencies: { 'express': '^4.0.0' },
    }))
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `import express from 'express'`)
    mkdirSync(join(testDir, 'node_modules', 'express'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'express', 'package.json'), JSON.stringify({ name: 'express' }))
    mkdirSync(join(testDir, 'node_modules', 'phantom-pkg'), { recursive: true })
    writeFileSync(join(testDir, 'node_modules', 'phantom-pkg', 'package.json'), JSON.stringify({ name: 'phantom-pkg', version: '1.0.0' }))

    const result = await sweep(testDir)
    assert.ok(result.phantomDeps)
    assert.ok(result.phantomDeps.some(p => p.name === 'phantom-pkg'))
  })
})
