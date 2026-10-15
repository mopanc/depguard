import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { advisoryToIncidents, normalizeVersionRange } from '../scripts/ghsa-import.js'
import type { GhsaAdvisory } from '../scripts/ghsa-import.js'
import { matchesCompromisedRange } from '../src/semver.js'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

function adv(overrides: Partial<GhsaAdvisory>): GhsaAdvisory {
  return {
    ghsa_id: 'GHSA-test-test-test',
    cve_id: null,
    summary: 'Malware in test',
    severity: 'critical',
    published_at: '2025-09-15T12:00:00Z',
    withdrawn_at: null,
    vulnerabilities: [],
    ...overrides,
  }
}

const npm = (name: string, range: string | null) => ({ package: { ecosystem: 'npm', name }, vulnerable_version_range: range })

describe('advisoryToIncidents', () => {
  it('imports every npm package of a multi-package advisory, not just the first', () => {
    const { incidents } = advisoryToIncidents(adv({
      summary: 'Malware in @tanstack/* packages',
      vulnerabilities: [npm('@tanstack/a', '= 1.0.1'), npm('@tanstack/b', '= 2.0.1'), npm('@tanstack/c', '= 3.0.1')],
    }))
    assert.deepEqual(incidents.map(i => i.name), ['@tanstack/a', '@tanstack/b', '@tanstack/c'])
  })

  it('combines every range listed for the same package', () => {
    const { incidents } = advisoryToIncidents(adv({
      vulnerabilities: [
        npm('eslint-config-prettier', '= 8.10.1'),
        npm('eslint-config-prettier', '= 9.1.1'),
        npm('eslint-config-prettier', '>= 10.1.6, <= 10.1.7'),
      ],
    }))
    assert.equal(incidents.length, 1)
    const range = incidents[0].incident.version
    for (const bad of ['8.10.1', '9.1.1', '10.1.6', '10.1.7']) assert.equal(matchesCompromisedRange(bad, range), true, bad)
    for (const clean of ['8.10.0', '9.1.0', '10.1.5', '10.1.8']) assert.equal(matchesCompromisedRange(clean, range), false, clean)
  })

  it('skips advisories about packages only indirectly exposed through a malicious dependency', () => {
    for (const summary of [
      'MetaMask SDK indirectly exposed via malicious debug@4.4.2 dependency',
      'Axios npm Supply Chain Incident Impacting @usebruno/cli',
    ]) {
      const r = advisoryToIncidents(adv({ summary, vulnerabilities: [npm('x', '>= 0.16.0, <= 0.33.0')] }))
      assert.deepEqual(r.incidents, [])
      assert.equal(r.skipped, 'indirect exposure')
    }
  })

  it('keeps hijack advisories that name the package itself', () => {
    const r = advisoryToIncidents(adv({ summary: 'debug@4.4.2 contains malware after npm account takeover', vulnerabilities: [npm('debug', '= 4.4.2')] }))
    assert.equal(r.incidents.length, 1)
    assert.equal(r.incidents[0].incident.version, '= 4.4.2')
    assert.equal(r.incidents[0].incident.origin, 'ghsa')
  })

  it('skips withdrawn advisories and non-npm entries', () => {
    assert.deepEqual(advisoryToIncidents(adv({ withdrawn_at: '2025-09-25T00:00:00Z', vulnerabilities: [npm('nx', '= 21.5.0')] })).incidents, [])
    const r = advisoryToIncidents(adv({ vulnerabilities: [{ package: { ecosystem: 'pip', name: 'requests' }, vulnerable_version_range: '= 1.0.0' }] }))
    assert.deepEqual(r.incidents, [])
  })

  it('uses the CVE id when present, the GHSA id otherwise', () => {
    assert.equal(advisoryToIncidents(adv({ cve_id: 'CVE-2021-4229', vulnerabilities: [npm('a', '= 1.0.0')] })).incidents[0].incident.cve, 'CVE-2021-4229')
    assert.equal(advisoryToIncidents(adv({ vulnerabilities: [npm('a', '= 1.0.0')] })).incidents[0].incident.cve, 'GHSA-test-test-test')
  })
})

describe('normalizeVersionRange', () => {
  it('maps every "all versions" spelling to the all sentinel', () => {
    for (const r of [null, '', '>= 0', '>=0', '> 0', '>= 0.0.0', '>= 0.0']) assert.equal(normalizeVersionRange(r), 'all', String(r))
  })

  it('leaves real ranges untouched', () => {
    assert.equal(normalizeVersionRange('>= 0.0.1'), '>= 0.0.1')
    assert.equal(normalizeVersionRange('<= 1.0.2'), '<= 1.0.2')
  })
})

describe('advisory-db exception list', () => {
  const exceptions = (JSON.parse(readFileSync(join(process.cwd(), 'src', 'data', 'advisory-db-exceptions.json'), 'utf-8')) as {
    exceptions: Array<{ package: string; id: string; reason: string }>
  }).exceptions

  it('keeps the known indirect-exposure advisories quarantined, each with a reason', () => {
    const has = (pkg: string, id: string) => exceptions.some(e => e.package === pkg && e.id === id && e.reason.length > 20)
    for (const pkg of ['@metamask/sdk', '@metamask/sdk-react', '@metamask/sdk-communication-layer']) {
      assert.ok(has(pkg, 'GHSA-qj3p-xc97-xw74'), pkg)
    }
    assert.ok(has('@usebruno/cli', 'CVE-2026-34841'))
  })
})
