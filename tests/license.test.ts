import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { checkLicenseCompatibility, knownLicenses } from '../src/license.js'

describe('checkLicenseCompatibility', () => {
  it('MIT dep is compatible with MIT target', () => {
    const result = checkLicenseCompatibility('MIT', 'MIT')
    assert.strictEqual(result.compatible, true)
    assert.strictEqual(result.license, 'MIT')
    assert.strictEqual(result.targetLicense, 'MIT')
  })

  it('MIT dep is compatible with GPL-3.0 target', () => {
    const result = checkLicenseCompatibility('MIT', 'GPL-3.0')
    assert.strictEqual(result.compatible, true)
  })

  it('GPL-3.0 dep is NOT compatible with MIT target', () => {
    const result = checkLicenseCompatibility('GPL-3.0', 'MIT')
    assert.strictEqual(result.compatible, false)
    assert.ok(result.reason.includes('more restrictive'))
  })

  it('Apache-2.0 dep is compatible with Apache-2.0 target', () => {
    const result = checkLicenseCompatibility('Apache-2.0', 'Apache-2.0')
    assert.strictEqual(result.compatible, true)
  })

  it('ISC dep is compatible with MIT target (same category)', () => {
    const result = checkLicenseCompatibility('ISC', 'MIT')
    assert.strictEqual(result.compatible, true)
  })

  it('BSD-3-Clause dep is compatible with Apache-2.0 target', () => {
    const result = checkLicenseCompatibility('BSD-3-Clause', 'Apache-2.0')
    assert.strictEqual(result.compatible, true)
  })

  it('AGPL-3.0 dep is NOT compatible with GPL-3.0 target', () => {
    const result = checkLicenseCompatibility('AGPL-3.0', 'GPL-3.0')
    assert.strictEqual(result.compatible, false)
  })

  it('LGPL-3.0 dep is compatible with GPL-3.0 target', () => {
    const result = checkLicenseCompatibility('LGPL-3.0', 'GPL-3.0')
    assert.strictEqual(result.compatible, true)
  })

  it('MPL-2.0 dep is compatible with GPL-3.0 target', () => {
    const result = checkLicenseCompatibility('MPL-2.0', 'GPL-3.0')
    assert.strictEqual(result.compatible, true)
  })

  it('MPL-2.0 dep is NOT compatible with MIT target', () => {
    const result = checkLicenseCompatibility('MPL-2.0', 'MIT')
    assert.strictEqual(result.compatible, false)
  })

  it('Unlicense dep is compatible with anything', () => {
    const result = checkLicenseCompatibility('Unlicense', 'AGPL-3.0')
    assert.strictEqual(result.compatible, true)
  })

  it('null license is not compatible', () => {
    const result = checkLicenseCompatibility(null, 'MIT')
    assert.strictEqual(result.compatible, false)
    assert.strictEqual(result.license, null)
    assert.ok(result.reason.includes('No license'))
  })

  it('UNLICENSED is not compatible', () => {
    const result = checkLicenseCompatibility('UNLICENSED', 'MIT')
    assert.strictEqual(result.compatible, false)
    assert.ok(result.reason.includes('UNLICENSED'))
  })

  it('unknown license requires manual review', () => {
    const result = checkLicenseCompatibility('CustomLicense-1.0', 'MIT')
    assert.strictEqual(result.compatible, false)
    assert.ok(result.reason.includes('Unknown license'))
  })

  it('unknown target license requires manual review', () => {
    const result = checkLicenseCompatibility('MIT', 'CustomTarget-1.0')
    assert.strictEqual(result.compatible, false)
    assert.ok(result.reason.includes('Unknown target license'))
  })

  it('normalizes common aliases (Apache 2.0 → Apache-2.0)', () => {
    const result = checkLicenseCompatibility('Apache 2.0', 'MIT')
    assert.strictEqual(result.compatible, true)
    assert.strictEqual(result.license, 'Apache-2.0')
  })

  it('CC0-1.0 is compatible with everything', () => {
    const result = checkLicenseCompatibility('CC0-1.0', 'MIT')
    assert.strictEqual(result.compatible, true)
  })

  it('handles dual license with OR — compatible if any option matches', () => {
    const result = checkLicenseCompatibility('MIT OR GPL-3.0', 'MIT')
    assert.strictEqual(result.compatible, true)
  })

  it('handles dual license with OR — incompatible if no option matches', () => {
    const result = checkLicenseCompatibility('GPL-3.0 OR AGPL-3.0', 'MIT')
    assert.strictEqual(result.compatible, false)
  })

  it('handles compound license with AND — all must be compatible', () => {
    const result = checkLicenseCompatibility('MIT AND ISC', 'Apache-2.0')
    assert.strictEqual(result.compatible, true)
  })

  it('handles compound license with AND — fails if any is incompatible', () => {
    const result = checkLicenseCompatibility('MIT AND GPL-3.0', 'MIT')
    assert.strictEqual(result.compatible, false)
  })

  it('detects source-available licenses as restrictive', () => {
    const result = checkLicenseCompatibility('SSPL-1.0', 'MIT')
    assert.strictEqual(result.compatible, false)
  })

  it('handles parenthesized SPDX expressions', () => {
    const result = checkLicenseCompatibility('(MIT OR Apache-2.0)', 'MIT')
    assert.strictEqual(result.compatible, true)
  })
})

describe('knownLicenses', () => {
  it('returns an array of known license identifiers', () => {
    const licenses = knownLicenses()
    assert.ok(Array.isArray(licenses))
    assert.ok(licenses.length > 10)
    assert.ok(licenses.includes('MIT'))
    assert.ok(licenses.includes('GPL-3.0'))
    assert.ok(licenses.includes('Apache-2.0'))
  })
})
