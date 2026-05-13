import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { satisfiesRange, matchesCompromisedRange } from '../src/semver.js'

describe('satisfiesRange', () => {
  it('returns true when version is in vulnerable range', () => {
    assert.strictEqual(satisfiesRange('4.17.19', '< 4.17.20'), true)
    assert.strictEqual(satisfiesRange('1.5.0', '>= 1.0.0, < 2.0.0'), true)
    assert.strictEqual(satisfiesRange('0.3.0', '>= 0.1.0, < 0.4.0'), true)
  })

  it('returns false when version is NOT in vulnerable range', () => {
    assert.strictEqual(satisfiesRange('4.17.21', '< 4.17.20'), false)
    assert.strictEqual(satisfiesRange('2.0.0', '>= 1.0.0, < 2.0.0'), false)
    assert.strictEqual(satisfiesRange('19.2.4', '< 0.4.2'), false)
    assert.strictEqual(satisfiesRange('5.0.0', '>= 1.0.0, < 3.0.0'), false)
  })

  it('handles exact version match', () => {
    assert.strictEqual(satisfiesRange('1.2.3', '= 1.2.3'), true)
    assert.strictEqual(satisfiesRange('1.2.4', '= 1.2.3'), false)
  })

  it('handles <= and >= operators', () => {
    assert.strictEqual(satisfiesRange('3.5.0', '<= 3.5.0'), true)
    assert.strictEqual(satisfiesRange('3.5.1', '<= 3.5.0'), false)
    assert.strictEqual(satisfiesRange('3.5.0', '>= 3.5.0'), true)
    assert.strictEqual(satisfiesRange('3.4.9', '>= 3.5.0'), false)
  })

  it('handles version with v prefix', () => {
    assert.strictEqual(satisfiesRange('v4.17.19', '< 4.17.20'), true)
    assert.strictEqual(satisfiesRange('v4.17.21', '< 4.17.20'), false)
  })

  it('returns true for wildcard or empty range', () => {
    assert.strictEqual(satisfiesRange('1.0.0', '*'), true)
    assert.strictEqual(satisfiesRange('1.0.0', ''), true)
  })

  it('returns true for unparseable version (safe default)', () => {
    assert.strictEqual(satisfiesRange('unknown', '< 4.0.0'), true)
  })

  it('handles real GitHub advisory ranges', () => {
    // React advisory for 0.4.x should NOT affect 19.x
    assert.strictEqual(satisfiesRange('19.2.4', '>= 0.4.0, < 0.4.2'), false)
    // Express advisory should affect 4.21.1 but not 5.0.0
    assert.strictEqual(satisfiesRange('4.21.1', '< 4.21.2'), true)
    assert.strictEqual(satisfiesRange('5.0.0', '< 4.21.2'), false)
  })

  it('handles OR clauses (||)', () => {
    // Version 1.5.0 should match the first clause
    assert.strictEqual(satisfiesRange('1.5.0', '>= 1.0.0, < 2.0.0 || >= 3.0.0, < 3.5.0'), true)
    // Version 3.2.0 should match the second clause
    assert.strictEqual(satisfiesRange('3.2.0', '>= 1.0.0, < 2.0.0 || >= 3.0.0, < 3.5.0'), true)
    // Version 2.5.0 should not match any clause
    assert.strictEqual(satisfiesRange('2.5.0', '>= 1.0.0, < 2.0.0 || >= 3.0.0, < 3.5.0'), false)
    // Version 4.0.0 should not match any clause
    assert.strictEqual(satisfiesRange('4.0.0', '>= 1.0.0, < 2.0.0 || >= 3.0.0, < 3.5.0'), false)
  })
})

describe('matchesCompromisedRange (FP-averse)', () => {
  it('treats "all", "*", "", ">= 0" as universal match for any parseable version', () => {
    assert.strictEqual(matchesCompromisedRange('1.2.3', 'all'), true)
    assert.strictEqual(matchesCompromisedRange('1.2.3', '*'), true)
    assert.strictEqual(matchesCompromisedRange('1.2.3', ''), true)
    assert.strictEqual(matchesCompromisedRange('1.2.3', '>= 0'), true)
    assert.strictEqual(matchesCompromisedRange('1.2.3', '>=0'), true)
  })

  it('exact version match (single comparator)', () => {
    assert.strictEqual(matchesCompromisedRange('1.2.3', '= 1.2.3'), true)
    assert.strictEqual(matchesCompromisedRange('1.2.4', '= 1.2.3'), false)
    assert.strictEqual(matchesCompromisedRange('1.2.3', '1.2.3'), true)
    assert.strictEqual(matchesCompromisedRange('1.2.4', '1.2.3'), false)
  })

  it('comma-separated list of exact versions (curated "0.7.29,0.8.0,1.0.0" format = OR)', () => {
    const range = '0.7.29,0.8.0,1.0.0'
    assert.strictEqual(matchesCompromisedRange('0.7.29', range), true)
    assert.strictEqual(matchesCompromisedRange('0.8.0', range), true)
    assert.strictEqual(matchesCompromisedRange('1.0.0', range), true)
    // Clean post-hijack versions must NOT match.
    assert.strictEqual(matchesCompromisedRange('1.0.39', range), false)
    assert.strictEqual(matchesCompromisedRange('0.7.30', range), false)
    assert.strictEqual(matchesCompromisedRange('2.0.0', range), false)
  })

  it('range with intersection: ">= 1.0.0, < 1.1.0"', () => {
    assert.strictEqual(matchesCompromisedRange('1.0.5', '>= 1.0.0, < 1.1.0'), true)
    assert.strictEqual(matchesCompromisedRange('1.1.0', '>= 1.0.0, < 1.1.0'), false)
    assert.strictEqual(matchesCompromisedRange('0.9.9', '>= 1.0.0, < 1.1.0'), false)
  })

  it('OR clauses', () => {
    const r = '>= 1.0.0, < 1.1.0 || >= 2.0.0, < 2.1.0'
    assert.strictEqual(matchesCompromisedRange('1.0.5', r), true)
    assert.strictEqual(matchesCompromisedRange('2.0.5', r), true)
    assert.strictEqual(matchesCompromisedRange('1.5.0', r), false)
    assert.strictEqual(matchesCompromisedRange('3.0.0', r), false)
  })

  it('FP-averse default: unparseable inputs return false', () => {
    assert.strictEqual(matchesCompromisedRange('', '>= 1.0.0'), false)
    assert.strictEqual(matchesCompromisedRange('not-a-version', '>= 1.0.0'), false)
    assert.strictEqual(matchesCompromisedRange('1.2.3', '>= not-a-version'), false)
    assert.strictEqual(matchesCompromisedRange('1.2.3', 'gibberish range here'), false)
  })

  it('regression: ua-parser-js@1.0.39 (clean post-hijack) NOT flagged by curated hijack range', () => {
    // The real curated incident.version string for the 2021 ua-parser-js hijack.
    const hijack = '0.7.29,0.8.0,1.0.0'
    assert.strictEqual(matchesCompromisedRange('1.0.39', hijack), false)
    // Hijacked versions themselves still match
    assert.strictEqual(matchesCompromisedRange('0.7.29', hijack), true)
    assert.strictEqual(matchesCompromisedRange('0.8.0', hijack), true)
    assert.strictEqual(matchesCompromisedRange('1.0.0', hijack), true)
  })
})
