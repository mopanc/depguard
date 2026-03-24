import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { analyzePublicationTimeline } from '../src/publication-analysis.js'
import type { NpmPackageData } from '../src/types.js'

function makePkg(time: Record<string, string>): NpmPackageData {
  return {
    name: 'test-pkg',
    description: 'test',
    'dist-tags': { latest: '1.0.0' },
    time,
    versions: {},
  } as NpmPackageData
}

describe('analyzePublicationTimeline', () => {
  it('returns none for normal publishing pattern', () => {
    const result = analyzePublicationTimeline(makePkg({
      created: '2024-01-01T00:00:00.000Z',
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '1.1.0': '2024-02-01T00:00:00.000Z',
      '1.2.0': '2024-03-01T00:00:00.000Z',
      '1.3.0': '2024-04-01T00:00:00.000Z',
    }))
    assert.strictEqual(result.riskLevel, 'none')
    assert.strictEqual(result.anomalies.length, 0)
    assert.strictEqual(result.totalVersions, 4)
  })

  it('detects burst publishing (8 versions in 1 hour, recent)', () => {
    const now = new Date()
    const recently = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
    const time: Record<string, string> = { created: '2024-01-01T00:00:00.000Z' }
    for (let i = 0; i < 8; i++) {
      const d = new Date(recently.getTime() + i * 60 * 60 * 1000) // 1 hour apart
      time[`1.0.${i}`] = d.toISOString()
    }
    const result = analyzePublicationTimeline(makePkg(time))
    assert.ok(result.anomalies.some(a => a.type === 'burst-publishing'))
    assert.ok(result.riskLevel === 'medium' || result.riskLevel === 'high')
  })

  it('detects dormant resurrection (2-year gap with recent republish)', () => {
    const now = new Date()
    const twoYearsAgo = new Date(now.getTime() - 800 * 24 * 60 * 60 * 1000)
    const recently = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000)
    const result = analyzePublicationTimeline(makePkg({
      created: twoYearsAgo.toISOString(),
      '1.0.0': twoYearsAgo.toISOString(),
      '2.0.0': recently.toISOString(),
    }))
    assert.ok(result.anomalies.some(a => a.type === 'dormant-resurrection'))
  })

  it('detects version jump (1.x to 6.x, recent)', () => {
    const now = new Date()
    const recent1 = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000)
    const recent2 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
    const result = analyzePublicationTimeline(makePkg({
      created: '2024-01-01T00:00:00.000Z',
      '1.0.0': recent1.toISOString(),
      '6.0.0': recent2.toISOString(),
    }))
    assert.ok(result.anomalies.some(a => a.type === 'version-jump'))
  })

  it('does not flag normal major bump (1.x to 2.x)', () => {
    const now = new Date()
    const recent1 = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000)
    const recent2 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
    const result = analyzePublicationTimeline(makePkg({
      created: '2024-01-01T00:00:00.000Z',
      '1.0.0': recent1.toISOString(),
      '2.0.0': recent2.toISOString(),
    }))
    assert.ok(!result.anomalies.some(a => a.type === 'version-jump'))
  })

  it('handles empty time field', () => {
    const result = analyzePublicationTimeline(makePkg({}))
    assert.strictEqual(result.riskLevel, 'none')
    assert.strictEqual(result.totalVersions, 0)
    assert.strictEqual(result.firstPublish, null)
  })

  it('handles single version', () => {
    const result = analyzePublicationTimeline(makePkg({
      created: '2024-01-01T00:00:00.000Z',
      '1.0.0': '2024-01-01T00:00:00.000Z',
    }))
    assert.strictEqual(result.riskLevel, 'none')
    assert.strictEqual(result.totalVersions, 1)
  })

  it('detects multiple anomalies and escalates risk', () => {
    const now = new Date()
    const threeYearsAgo = new Date(now.getTime() - 1100 * 24 * 60 * 60 * 1000)
    const recently = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000)
    const time: Record<string, string> = {
      created: threeYearsAgo.toISOString(),
      '1.0.0': threeYearsAgo.toISOString(),
    }
    // Dormant resurrection + burst publishing (recent)
    for (let i = 0; i < 8; i++) {
      const d = new Date(recently.getTime() + i * 60 * 60 * 1000) // 1 hour apart
      time[`5.0.${i}`] = d.toISOString()
    }
    const result = analyzePublicationTimeline(makePkg(time))
    assert.ok(result.anomalies.length >= 1)
    assert.ok(result.riskLevel === 'medium' || result.riskLevel === 'high')
  })

  it('flags dormant gap only when republish is recent', () => {
    const now = new Date()
    const longAgo = new Date(now.getTime() - 500 * 24 * 60 * 60 * 1000)
    const recently = new Date(now.getTime() - 15 * 24 * 60 * 60 * 1000)
    const result = analyzePublicationTimeline(makePkg({
      created: longAgo.toISOString(),
      '1.0.0': longAgo.toISOString(),
      '1.1.0': recently.toISOString(),
    }))
    assert.ok(result.anomalies.some(a => a.type === 'dormant-resurrection'))
  })

  it('flags extreme burst as high severity (recent)', () => {
    const now = new Date()
    const recently = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000) // 7 days ago
    const time: Record<string, string> = { created: '2024-01-01T00:00:00.000Z' }
    for (let i = 0; i < 15; i++) {
      const d = new Date(recently.getTime() + i * 60 * 1000) // 1 minute apart
      time[`1.0.${i}`] = d.toISOString()
    }
    const result = analyzePublicationTimeline(makePkg(time))
    assert.ok(result.anomalies.some(a => a.type === 'burst-publishing' && a.severity === 'high'))
  })
})
