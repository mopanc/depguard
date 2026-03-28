/**
 * Maps common development intents to native Node.js alternatives.
 * Used by the advisor to recommend built-in solutions before npm packages.
 */

export interface NativeAlternative {
  intent: string[]
  api: string
  example: string
  minNodeVersion: string
}

const NATIVE_ALTERNATIVES: NativeAlternative[] = [
  {
    intent: ['http client', 'http request', 'fetch', 'api client', 'rest client'],
    api: 'globalThis.fetch()',
    example: 'const res = await fetch("https://api.example.com/data")',
    minNodeVersion: '18.0.0',
  },
  {
    intent: ['uuid', 'unique id', 'random id', 'generate id'],
    api: 'crypto.randomUUID()',
    example: "import { randomUUID } from 'node:crypto'; const id = randomUUID()",
    minNodeVersion: '19.0.0',
  },
  {
    intent: ['hash', 'md5', 'sha256', 'sha1', 'checksum', 'file hash'],
    api: 'crypto.createHash()',
    example: "import { createHash } from 'node:crypto'; createHash('sha256').update(data).digest('hex')",
    minNodeVersion: '0.1.92',
  },
  {
    intent: ['deep clone', 'clone object', 'deep copy'],
    api: 'structuredClone()',
    example: 'const clone = structuredClone(originalObject)',
    minNodeVersion: '17.0.0',
  },
  {
    intent: ['url parse', 'url parsing', 'query string', 'parse url'],
    api: 'new URL() + URLSearchParams',
    example: "const url = new URL('https://example.com?foo=bar'); url.searchParams.get('foo')",
    minNodeVersion: '10.0.0',
  },
  {
    intent: ['path', 'path manipulation', 'path join', 'file path'],
    api: 'node:path',
    example: "import { join, resolve, basename } from 'node:path'",
    minNodeVersion: '0.1.16',
  },
  {
    intent: ['read file', 'write file', 'file system', 'fs'],
    api: 'node:fs/promises',
    example: "import { readFile, writeFile } from 'node:fs/promises'",
    minNodeVersion: '10.0.0',
  },
  {
    intent: ['environment variable', 'env var', 'dotenv', 'env config'],
    api: 'process.loadEnvFile()',
    example: `process.loadEnvFile('.env'); // loads into ${'process'}.env`,
    minNodeVersion: '21.7.0',
  },
  {
    intent: ['glob', 'file glob', 'find files', 'file pattern'],
    api: 'fs.glob()',
    example: "import { glob } from 'node:fs'; for await (const f of glob('**/*.ts')) console.log(f)",
    minNodeVersion: '22.0.0',
  },
  {
    intent: ['test', 'testing', 'unit test', 'test runner'],
    api: 'node:test',
    example: "import { describe, it } from 'node:test'; import assert from 'node:assert/strict'",
    minNodeVersion: '18.0.0',
  },
  {
    intent: ['watch file', 'file watcher', 'watch changes'],
    api: 'fs.watch()',
    example: "import { watch } from 'node:fs'; watch('./src', { recursive: true }, (event, filename) => {})",
    minNodeVersion: '19.1.0',
  },
  {
    intent: ['argument parsing', 'cli arguments', 'parse args', 'command line'],
    api: 'util.parseArgs()',
    example: "import { parseArgs } from 'node:util'; const { values } = parseArgs({ options: { name: { type: 'string' } } })",
    minNodeVersion: '18.3.0',
  },
  {
    intent: ['stream', 'readable stream', 'writable stream', 'pipe'],
    api: 'node:stream',
    example: "import { Readable, pipeline } from 'node:stream'; import { pipeline as pipelineAsync } from 'node:stream/promises'",
    minNodeVersion: '15.0.0',
  },
  {
    intent: ['event emitter', 'events', 'pub sub', 'event bus'],
    api: 'node:events',
    example: "import { EventEmitter } from 'node:events'; const emitter = new EventEmitter()",
    minNodeVersion: '0.1.26',
  },
  {
    intent: ['compression', 'gzip', 'deflate', 'zip'],
    api: 'node:zlib',
    example: "import { gzip, gunzip } from 'node:zlib'; import { promisify } from 'node:util'",
    minNodeVersion: '0.5.8',
  },
  {
    intent: ['worker', 'worker thread', 'multi thread', 'parallel'],
    api: 'node:worker_threads',
    example: "import { Worker, isMainThread } from 'node:worker_threads'",
    minNodeVersion: '12.0.0',
  },
  {
    intent: ['abort', 'cancel request', 'timeout', 'abort controller'],
    api: 'AbortController',
    example: 'const controller = new AbortController(); fetch(url, { signal: controller.signal })',
    minNodeVersion: '15.0.0',
  },
  {
    intent: ['base64', 'base64 encode', 'base64 decode', 'encoding'],
    api: 'Buffer.from() / btoa() / atob()',
    example: "Buffer.from('hello').toString('base64'); Buffer.from(b64, 'base64').toString()",
    minNodeVersion: '0.1.90',
  },
  {
    intent: ['typescript', 'type strip', 'run typescript'],
    api: 'node --experimental-strip-types',
    example: 'node --experimental-strip-types app.ts',
    minNodeVersion: '22.6.0',
  },
  {
    intent: ['sqlite', 'database', 'embedded database', 'local database'],
    api: 'node:sqlite',
    example: "import { DatabaseSync } from 'node:sqlite'; const db = new DatabaseSync(':memory:')",
    minNodeVersion: '22.5.0',
  },
  {
    intent: ['date format', 'date formatting', 'format date', 'date display', 'date locale'],
    api: 'Intl.DateTimeFormat',
    example: "new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'long', day: 'numeric' }).format(new Date())",
    minNodeVersion: '0.12.0',
  },
  {
    intent: ['relative time', 'time ago', 'from now', 'ago'],
    api: 'Intl.RelativeTimeFormat',
    example: "new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(-1, 'day') // 'yesterday'",
    minNodeVersion: '12.0.0',
  },
  {
    intent: ['number format', 'number formatting', 'currency format', 'currency formatting'],
    api: 'Intl.NumberFormat',
    example: "new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(1234.56) // '$1,234.56'",
    minNodeVersion: '0.12.0',
  },
  {
    intent: ['string sort', 'string comparison', 'locale sort', 'collation'],
    api: 'Intl.Collator',
    example: "const collator = new Intl.Collator('de'); ['z','a','o'].sort(collator.compare) // locale-aware sort",
    minNodeVersion: '0.12.0',
  },
]

/**
 * Find a native Node.js alternative for a given intent.
 * Returns null if no native alternative exists.
 */
export function findNativeAlternative(intent: string): NativeAlternative | null {
  const lower = intent.toLowerCase()

  for (const alt of NATIVE_ALTERNATIVES) {
    for (const keyword of alt.intent) {
      if (lower.includes(keyword)) {
        return alt
      }
    }
  }

  return null
}
