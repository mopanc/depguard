import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { findNativeAlternative } from '../src/native-alternatives.js'

describe('findNativeAlternative', () => {
  it('finds fetch for http client', () => {
    const result = findNativeAlternative('http client')
    assert.ok(result)
    assert.ok(result.api.includes('fetch'))
    assert.strictEqual(result.minNodeVersion, '18.0.0')
  })

  it('finds crypto.randomUUID for uuid', () => {
    const result = findNativeAlternative('I need a uuid generator')
    assert.ok(result)
    assert.ok(result.api.includes('randomUUID'))
  })

  it('finds structuredClone for deep clone', () => {
    const result = findNativeAlternative('deep clone objects')
    assert.ok(result)
    assert.ok(result.api.includes('structuredClone'))
  })

  it('finds parseArgs for cli arguments', () => {
    const result = findNativeAlternative('parse command line arguments')
    assert.ok(result)
    assert.ok(result.api.includes('parseArgs'))
  })

  it('finds node:test for testing', () => {
    const result = findNativeAlternative('unit test runner')
    assert.ok(result)
    assert.ok(result.api.includes('node:test'))
  })

  it('finds node:sqlite for database', () => {
    const result = findNativeAlternative('embedded database')
    assert.ok(result)
    assert.ok(result.api.includes('sqlite'))
  })

  it('returns null for intents without native solution', () => {
    assert.strictEqual(findNativeAlternative('date formatting'), null)
    assert.strictEqual(findNativeAlternative('email sending'), null)
    assert.strictEqual(findNativeAlternative('image processing'), null)
    assert.strictEqual(findNativeAlternative('pdf generation'), null)
  })

  it('includes example code', () => {
    const result = findNativeAlternative('http client')
    assert.ok(result)
    assert.ok(result.example.length > 0)
  })
})
