#!/usr/bin/env node --import tsx
/**
 * One-shot migration: stamp `origin` field on every existing incident in
 * src/data/advisory-db.json. Curated entries (the original 24 hand-verified
 * packages from before the GHSA auto-refresh) get `origin: 'curated'`;
 * everything else gets `origin: 'ghsa'`.
 *
 * Idempotent — running twice has no effect after the first run.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = join(__dirname, '..', 'src', 'data', 'advisory-db.json')

const CURATED = new Set<string>([
  'babelcli', 'claud-code', 'cloude', 'cloude-code', 'coa', 'colors',
  'crossenv', 'd3.js', 'electorn', 'eslint-scope', 'event-stream',
  'fabric-js', 'faker', 'flatmap-stream', 'gruntcli', 'http-proxy.js',
  'jquery.js', 'loadsh', 'node-ipc', 'peacenotwar', 'rc', 'suport-color',
  'ua-parser-js', 'veim',
])

const db = JSON.parse(readFileSync(DB_PATH, 'utf-8'))
let curated = 0
let ghsa = 0
let alreadySet = 0

for (const [name, pkg] of Object.entries<{ incidents: Array<{ origin?: string }> }>(db.packages)) {
  const origin = CURATED.has(name) ? 'curated' : 'ghsa'
  for (const incident of pkg.incidents) {
    if (incident.origin) { alreadySet++; continue }
    incident.origin = origin
    if (origin === 'curated') curated++
    else ghsa++
  }
}

writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n')
console.log(`Migration done:
  curated incidents stamped: ${curated}
  ghsa incidents stamped:    ${ghsa}
  already had origin:        ${alreadySet}
  wrote: ${DB_PATH}`)
