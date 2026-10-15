/**
 * Precision gate for the bundled advisory database (policy
 * `depguard-false-positive-aversion-policy`). Runs against the real data in
 * src/data, in CI and in the daily scan between the refresh and the commit, so
 * a database update that would flag clean software never reaches main.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { getCompromisedIncidents } from '../src/advisory-db.js'

const flagged = (name: string, version: string) => getCompromisedIncidents(name, version).map(i => i.cve ?? i.description)

/**
 * Versions known to be clean: the releases on either side of documented
 * hijacks, and the versions that were current before or after each incident.
 * Never add a version here without checking its publish date and the
 * official advisory range.
 */
const KNOWN_CLEAN: Array<[string, string]> = [
  ['node-ipc', '9.2.1'], ['node-ipc', '10.1.0'], ['node-ipc', '10.1.3'],
  ['debug', '4.4.1'], ['debug', '4.4.3'], ['debug', '4.3.4'],
  ['color', '5.0.0'], ['color', '4.2.3'],
  ['color-convert', '2.0.1'], ['color-convert', '3.1.0'],
  ['color-name', '1.1.4'], ['color-name', '2.0.0'],
  ['color-string', '1.9.1'], ['error-ex', '1.3.2'], ['is-arrayish', '0.3.2'], ['simple-swizzle', '0.2.2'],
  ['eslint-config-prettier', '8.10.0'], ['eslint-config-prettier', '9.1.0'],
  ['eslint-config-prettier', '10.1.5'], ['eslint-config-prettier', '10.1.8'],
  ['eslint-plugin-prettier', '4.2.1'], ['eslint-plugin-prettier', '5.5.5'],
  ['colors', '1.4.0'],
  ['ua-parser-js', '0.7.28'], ['ua-parser-js', '0.7.30'], ['ua-parser-js', '1.0.39'],
  ['event-stream', '3.3.5'], ['event-stream', '4.0.1'],
  ['eslint-scope', '3.7.1'], ['eslint-scope', '3.7.3'],
  ['rc', '1.2.8'], ['coa', '2.0.2'],
  ['axios', '1.14.0'], ['axios', '1.12.2'], ['axios', '0.30.3'],
]

/** Documented incidents that must keep being detected. */
const KNOWN_BAD: Array<[string, string]> = [
  ['node-ipc', '10.1.1'], ['node-ipc', '10.1.2'],
  ['debug', '4.4.2'], ['color', '5.0.1'], ['colors', '1.4.1'],
  ['ua-parser-js', '0.7.29'], ['event-stream', '3.3.6'], ['eslint-config-prettier', '10.1.7'],
]

describe('advisory database precision', () => {
  for (const [name, version] of KNOWN_CLEAN) {
    it(`does not flag clean ${name}@${version}`, () => {
      assert.deepEqual(flagged(name, version), [])
    })
  }

  it('does not flag any of the most popular npm packages at their current version', () => {
    const scanPath = join(process.cwd(), 'docs', 'data', 'daily-scan.json')
    if (!existsSync(scanPath)) return
    const scan = JSON.parse(readFileSync(scanPath, 'utf-8')) as { packages: Array<{ name: string; version: string }> }
    assert.ok(scan.packages.length > 100)
    const hits = scan.packages
      .map(p => ({ pkg: `${p.name}@${p.version}`, ids: flagged(p.name, p.version) }))
      .filter(h => h.ids.length > 0)
    assert.deepEqual(hits, [])
  })
})

describe('advisory database recall', () => {
  for (const [name, version] of KNOWN_BAD) {
    it(`still flags ${name}@${version}`, () => {
      assert.ok(flagged(name, version).length > 0)
    })
  }
})
