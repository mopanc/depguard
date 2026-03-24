import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { analyzeMaintainers } from '../src/maintainer-analysis.js'
import type { NpmPackageData } from '../src/types.js'

function makePkg(overrides: Partial<NpmPackageData> = {}): NpmPackageData {
  const time: Record<string, string> = { created: '2022-01-01T00:00:00.000Z' }
  for (let i = 0; i < 25; i++) {
    time[`1.${i}.0`] = `2022-0${Math.min(9, 1 + Math.floor(i / 3))}-01T00:00:00.000Z`
  }
  return {
    name: 'test-pkg',
    description: 'test',
    'dist-tags': { latest: '1.24.0' },
    time,
    versions: {},
    maintainers: [
      { name: 'alice', email: 'alice@company.com' },
      { name: 'bob', email: 'bob@company.com' },
      { name: 'carol', email: 'carol@company.com' },
    ],
    ...overrides,
  } as NpmPackageData
}

describe('analyzeMaintainers', () => {
  it('returns none for healthy package', () => {
    const result = analyzeMaintainers(makePkg())
    assert.strictEqual(result.riskLevel, 'none')
    assert.strictEqual(result.flags.length, 0)
    assert.strictEqual(result.maintainerCount, 3)
  })

  it('flags single maintainer on mature package', () => {
    const result = analyzeMaintainers(makePkg({
      maintainers: [{ name: 'solo' }],
    }))
    assert.ok(result.flags.some(f => f.includes('Single maintainer')))
    assert.strictEqual(result.riskLevel, 'low')
  })

  it('flags new package with single maintainer', () => {
    const recentTime: Record<string, string> = {
      created: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
      '1.0.0': new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    }
    const result = analyzeMaintainers(makePkg({
      maintainers: [{ name: 'newbie' }],
      time: recentTime,
    }))
    assert.ok(result.flags.some(f => f.includes('less than 30 days')))
  })

  it('flags free email on enterprise package', () => {
    // Need 50+ versions to trigger this check
    const time: Record<string, string> = { created: '2020-01-01T00:00:00.000Z' }
    for (let i = 0; i < 55; i++) {
      time[`1.${i}.0`] = `2020-0${Math.min(9, 1 + Math.floor(i / 7))}-01T00:00:00.000Z`
    }
    const result = analyzeMaintainers(makePkg({
      maintainers: [{ name: 'dev', email: 'dev@gmail.com' }],
      time,
    }))
    assert.ok(result.flags.some(f => f.includes('free email')))
  })

  it('flags no maintainers', () => {
    const result = analyzeMaintainers(makePkg({
      maintainers: [],
    }))
    assert.ok(result.flags.some(f => f.includes('No maintainers')))
  })

  it('flags large team', () => {
    const bigTeam = Array.from({ length: 12 }, (_, i) => ({
      name: `dev${i}`,
      email: `dev${i}@company.com`,
    }))
    const result = analyzeMaintainers(makePkg({
      maintainers: bigTeam,
    }))
    assert.ok(result.flags.some(f => f.includes('Large maintainer team')))
  })

  it('handles missing maintainers field gracefully', () => {
    const result = analyzeMaintainers(makePkg({
      maintainers: undefined,
    }))
    assert.ok(result.flags.some(f => f.includes('No maintainers')))
    assert.strictEqual(result.maintainerCount, 0)
  })

  it('escalates risk with multiple flags', () => {
    const time: Record<string, string> = { created: '2020-01-01T00:00:00.000Z' }
    for (let i = 0; i < 55; i++) {
      time[`1.${i}.0`] = `2020-0${Math.min(9, 1 + Math.floor(i / 7))}-01T00:00:00.000Z`
    }
    const result = analyzeMaintainers(makePkg({
      maintainers: [{ name: 'solo', email: 'solo@gmail.com' }],
      time,
    }))
    // Single maintainer + free email = at least 2 flags
    assert.ok(result.flags.length >= 2)
    assert.ok(result.riskLevel === 'medium' || result.riskLevel === 'high')
  })
})
