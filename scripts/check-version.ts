#!/usr/bin/env node --import tsx
/**
 * Verifies that DEPGUARD_VERSION in src/version.ts matches package.json#version.
 * src/version.ts is the single source of truth; this script just guards against
 * a forgotten update on either side. Wired into `prepublishOnly` via `npm run check`.
 * Exits 0 on match, 1 on mismatch.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { DEPGUARD_VERSION } from '../src/version.js'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as { version?: unknown }

if (typeof pkg.version !== 'string' || !pkg.version) {
  console.error('check-version: package.json#version is missing or not a string')
  process.exit(1)
}

if (pkg.version !== DEPGUARD_VERSION) {
  console.error(
    `check-version: mismatch - package.json is ${pkg.version}, src/version.ts is ${DEPGUARD_VERSION}. ` +
    `Update both before publishing.`,
  )
  process.exit(1)
}

console.log(`check-version: OK (${DEPGUARD_VERSION})`)
