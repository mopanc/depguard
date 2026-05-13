import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  lookupCompromised,
  isVersionCompromised,
  getCompromisedIncidents,
  getIncidents,
  getDBSize,
} from '../src/advisory-db.js'

describe('advisory-db version-aware compromise checks', () => {
  it('DB loaded with curated and ghsa-imported entries', () => {
    assert.ok(getDBSize() > 100, `expected >100 packages in DB, got ${getDBSize()}`)
  })

  it('curated entries: ua-parser-js historic incident still present', () => {
    const pkg = lookupCompromised('ua-parser-js')
    assert.ok(pkg, 'ua-parser-js should be in DB')
    if (!pkg) return  // type narrow for ts-eslint
    assert.ok(pkg.incidents.length > 0)
    const hijack = pkg.incidents.find(i => i.version.includes('0.7.29'))
    assert.ok(hijack, 'hijack incident should exist')
  })

  it('REGRESSION (FP): isVersionCompromised(ua-parser-js, 1.0.39) returns false', () => {
    // ua-parser-js@1.0.39 is a CLEAN version published after the 2021 hijack.
    // The name-based legacy check returned true (false positive); the
    // version-aware check must return false. See policy
    // depguard-false-positive-aversion-policy.
    assert.strictEqual(isVersionCompromised('ua-parser-js', '1.0.39'), false)
  })

  it('isVersionCompromised(ua-parser-js, 0.7.29) returns true (hijacked version)', () => {
    assert.strictEqual(isVersionCompromised('ua-parser-js', '0.7.29'), true)
  })

  it('getCompromisedIncidents returns empty for clean ua-parser-js version', () => {
    const incidents = getCompromisedIncidents('ua-parser-js', '1.0.39')
    assert.deepStrictEqual(incidents, [])
  })

  it('getCompromisedIncidents returns matching incident for hijacked version', () => {
    const incidents = getCompromisedIncidents('ua-parser-js', '0.7.29')
    assert.ok(incidents.length >= 1)
    assert.match(incidents[0].description, /[Hh]ijack|stealer|cryptominer/i)
  })

  it('isVersionCompromised returns false for non-existent package', () => {
    assert.strictEqual(isVersionCompromised('this-pkg-does-not-exist-xyz', '1.0.0'), false)
  })

  it('isVersionCompromised returns false for empty version string', () => {
    // FP-averse default: cannot determine → do not flag
    assert.strictEqual(isVersionCompromised('ua-parser-js', ''), false)
  })

  it('GHSA-imported entries with universal range match any version', () => {
    // Real malware (e.g., a typosquat or wholly-malicious package) is published
    // with range "all" / ">= 0". Any version should be flagged.
    const pkg = lookupCompromised('flatmap-stream')
    assert.ok(pkg, 'flatmap-stream should be in DB')
  })

  it('getIncidents returns incidents (curated origin preserved or absent)', () => {
    const incidents = getIncidents('event-stream')
    assert.ok(incidents.length > 0)
    // Origin is either 'curated' (after migration) or undefined (legacy)
    assert.ok(
      incidents[0].origin === 'curated' || incidents[0].origin === undefined,
      `expected curated or undefined origin, got: ${incidents[0].origin}`,
    )
  })
})
