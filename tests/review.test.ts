import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { review } from '../src/review.js'

let testDir: string

beforeEach(() => {
  testDir = join(tmpdir(), `depguard-review-test-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  mkdirSync(testDir, { recursive: true })
})

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }) } catch { /* ok */ }
})

// ========================
// Console.log detection
// ========================

describe('console.log detection', () => {
  it('detects console.log in production code', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
const x = 1
console.log('debug value:', x)
export default x
`)
    const result = await review(testDir)
    assert.ok(result.findings.some(f => f.type === 'console-log'))
    const finding = result.findings.find(f => f.type === 'console-log')
    assert.strictEqual(finding?.line, 3)
  })

  it('skips console.log in test files', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.test.ts'), `
console.log('test output')
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'console-log'))
  })

  it('skips console.log in logger files', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'logger.ts'), `
export function log(msg: string) { console.log(msg) }
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'console-log'))
  })

  it('skips console.log in comments', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
// console.log('this is a comment')
const x = 1
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'console-log'))
  })
})

// ========================
// Empty catch detection
// ========================

describe('empty catch detection', () => {
  it('detects single-line empty catch', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
try { doSomething() } catch (e) {}
`)
    const result = await review(testDir)
    assert.ok(result.findings.some(f => f.type === 'empty-catch'))
  })

  it('detects multi-line empty catch', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
try {
  doSomething()
} catch (e) {
}
`)
    const result = await review(testDir)
    assert.ok(result.findings.some(f => f.type === 'empty-catch'))
  })

  it('does not flag catch with body', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
try { doSomething() } catch (e) { handleError(e) }
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'empty-catch'))
  })
})

// ========================
// Abandoned TODO detection
// ========================

describe('abandoned TODO detection', () => {
  it('detects TODO without issue reference', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
// TODO: fix this later
const x = 1
`)
    const result = await review(testDir)
    assert.ok(result.findings.some(f => f.type === 'abandoned-todo'))
  })

  it('skips TODO with issue reference', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
// TODO: fix this #123
const x = 1
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'abandoned-todo'))
  })

  it('skips TODO with URL', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
// TODO: see https://github.com/org/repo/issues/1
const x = 1
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'abandoned-todo'))
  })
})

// ========================
// Broken imports detection
// ========================

describe('broken imports detection', () => {
  it('detects import of nonexistent file', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
import { helper } from './nonexistent'
`)
    const result = await review(testDir)
    assert.ok(result.findings.some(f => f.type === 'broken-import'))
    assert.strictEqual(result.findings.find(f => f.type === 'broken-import')?.severity, 'error')
  })

  it('resolves .ts extension correctly', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'utils.ts'), 'export const x = 1')
    writeFileSync(join(testDir, 'src', 'app.ts'), `
import { x } from './utils'
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'broken-import'))
  })

  it('resolves index.ts in directory', async () => {
    mkdirSync(join(testDir, 'src', 'lib'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'lib', 'index.ts'), 'export const x = 1')
    writeFileSync(join(testDir, 'src', 'app.ts'), `
import { x } from './lib'
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'broken-import'))
  })

  it('ignores node_modules packages', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
import express from 'express'
`)
    const result = await review(testDir)
    assert.ok(!result.findings.some(f => f.type === 'broken-import'))
  })
})

// ========================
// Empty tests detection (full mode)
// ========================

describe('empty tests detection', () => {
  it('flags test file with no assertions', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.test.ts'), `
// This test file is empty
const x = 1
`)
    const result = await review(testDir, { mode: 'full' })
    assert.ok(result.findings.some(f => f.type === 'empty-test'))
  })

  it('passes test file with assertions', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.test.ts'), `
import { describe, it } from 'node:test'
import assert from 'node:assert'
describe('app', () => { it('works', () => { assert.ok(true) }) })
`)
    const result = await review(testDir, { mode: 'full' })
    assert.ok(!result.findings.some(f => f.type === 'empty-test'))
  })

  it('does not check non-test files for assertions', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
const x = 1
`)
    const result = await review(testDir, { mode: 'full' })
    assert.ok(!result.findings.some(f => f.type === 'empty-test'))
  })
})

// ========================
// Orphan files detection (full mode)
// ========================

describe('orphan files detection', () => {
  it('flags file not imported by anyone', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'used.ts'), 'export const x = 1')
    writeFileSync(join(testDir, 'src', 'orphan.ts'), 'export const y = 2')
    writeFileSync(join(testDir, 'src', 'main.ts'), `import { x } from './used'`)

    const result = await review(testDir, { mode: 'full' })
    assert.ok(result.findings.some(f => f.type === 'orphan-file' && f.file.includes('orphan.ts')))
  })

  it('does not flag imported file', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'utils.ts'), 'export const x = 1')
    writeFileSync(join(testDir, 'src', 'main.ts'), `import { x } from './utils'`)

    const result = await review(testDir, { mode: 'full' })
    assert.ok(!result.findings.some(f => f.type === 'orphan-file' && f.file.includes('utils.ts')))
  })

  it('does not flag entry point files', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), 'export const x = 1')

    const result = await review(testDir, { mode: 'full' })
    assert.ok(!result.findings.some(f => f.type === 'orphan-file' && f.file.includes('index.ts')))
  })
})

// ========================
// Integration
// ========================

describe('review integration', () => {
  it('quick mode does not run cross-file checks', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'orphan.ts'), 'export const y = 2')
    writeFileSync(join(testDir, 'src', 'app.test.ts'), 'const x = 1') // empty test

    const result = await review(testDir, { mode: 'quick' })
    assert.ok(!result.findings.some(f => f.type === 'orphan-file'))
    assert.ok(!result.findings.some(f => f.type === 'empty-test'))
  })

  it('full mode includes cross-file checks', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'orphan.ts'), 'export const y = 2')
    writeFileSync(join(testDir, 'src', 'app.test.ts'), 'const x = 1') // empty test

    const result = await review(testDir, { mode: 'full' })
    assert.strictEqual(result.mode, 'full')
    // At least one of orphan or empty test should be found
    assert.ok(result.totalFindings > 0)
  })

  it('returns zero findings for clean project', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'index.ts'), `
export function add(a: number, b: number): number {
  return a + b
}
`)
    const result = await review(testDir)
    assert.strictEqual(result.totalFindings, 0)
    assert.ok(result.summary.includes('Clean code'))
  })

  it('returns correct summary', async () => {
    mkdirSync(join(testDir, 'src'), { recursive: true })
    writeFileSync(join(testDir, 'src', 'app.ts'), `
console.log('debug')
// TODO: fix this
try { x() } catch (e) {}
`)
    const result = await review(testDir)
    assert.ok(result.summary.includes('console'))
    assert.ok(result.summary.includes('TODO'))
    assert.ok(result.note.length > 0)
  })

  it('handles empty project', async () => {
    const result = await review(testDir)
    assert.strictEqual(result.filesAnalyzed, 0)
    assert.strictEqual(result.totalFindings, 0)
  })
})
