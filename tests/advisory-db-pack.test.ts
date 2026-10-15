import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { compactAdvisoryDb } from '../scripts/pack-advisory-db.mjs'
import { expandCompromisedPackage } from '../src/advisory-db.js'
import { matchesCompromisedRange } from '../src/semver.js'

describe('packed advisory database', () => {
  it('round-trips every package of the real database without losing information', () => {
    const data = JSON.parse(readFileSync(join(process.cwd(), 'src', 'data', 'advisory-db.json'), 'utf-8'))
    const packed = compactAdvisoryDb(data)
    for (const [name, pkg] of Object.entries(data.packages)) {
      assert.deepEqual(expandCompromisedPackage(name, packed.packages[name]), pkg, name)
    }
  })

  it('keeps origin, so curated and imported entries stay distinguishable', () => {
    const packed = compactAdvisoryDb({
      version: 'x',
      packages: {
        a: { compromised: true, severity: 'critical', incidents: [{ version: 'all', type: 'supply-chain', date: 'd', cve: null, description: 'Malware in a', origin: 'ghsa' }] },
        b: { compromised: true, severity: 'critical', incidents: [{ version: '= 1.0.0', type: 'account-hijack', date: 'd', cve: 'CVE-1', description: 'Hijacked' }] },
      },
    })
    assert.equal(packed.packages.a.incidents[0].origin, 'ghsa')
    assert.equal('origin' in packed.packages.b.incidents[0], false)
    assert.equal(expandCompromisedPackage('b', packed.packages.b).incidents[0].type, 'account-hijack')
  })

  it('never turns a missing range into "all versions"', () => {
    const pkg = expandCompromisedPackage('x', { incidents: [{ date: 'd', cve: null }] })
    assert.equal(matchesCompromisedRange('1.0.0', pkg.incidents[0].version), false)
  })
})
