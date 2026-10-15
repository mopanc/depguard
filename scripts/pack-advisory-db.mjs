#!/usr/bin/env node
/**
 * Writes the advisory database that ships in the npm package.
 *
 * src/data/advisory-db.json stays pretty-printed so the daily refresh produces
 * readable git diffs. The copy in dist/data is minified and drops fields whose
 * value the loader can restore (see expandCompromisedPackage in
 * src/advisory-db.ts): `compromised: true`, `type: "supply-chain"`, and the
 * generic "Malware in <name>" description. `origin` is always kept, because a
 * missing origin means "curated" to the loader.
 *
 * Run by `npm run build` after the data files are copied to dist/data.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

export function compactAdvisoryDb(data) {
  const packages = {}
  for (const [name, pkg] of Object.entries(data.packages)) {
    const out = {}
    if (pkg.compromised !== true) out.compromised = pkg.compromised
    out.severity = pkg.severity
    out.incidents = pkg.incidents.map(i => {
      const inc = { version: i.version, date: i.date, cve: i.cve }
      if (i.type !== 'supply-chain') inc.type = i.type
      if (i.description !== `Malware in ${name}`) inc.description = i.description
      if (i.origin !== undefined) inc.origin = i.origin
      return inc
    })
    packages[name] = out
  }
  return { ...data, compact: 1, packages }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..')
  const src = join(root, 'src', 'data', 'advisory-db.json')
  const dest = join(root, 'dist', 'data', 'advisory-db.json')
  const data = JSON.parse(readFileSync(src, 'utf-8'))
  const packed = JSON.stringify(compactAdvisoryDb(data))
  writeFileSync(dest, packed)
  console.log(`advisory-db: ${Object.keys(data.packages).length} packages, ${(packed.length / 1e6).toFixed(1)} MB packed`)
}
