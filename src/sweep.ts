/**
 * Dead dependency detection.
 *
 * Scans a project's source files for import/require statements and
 * cross-references with package.json to find unused dependencies.
 *
 * Purely filesystem-based — zero network calls.
 * Zero dependencies — only Node.js built-ins.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, extname, resolve } from 'node:path'
import type { SweepResult, SweepOptions, SweepDepResult, DepUsageReason, PhantomDep } from './types.js'

/** File extensions to scan for imports */
const SOURCE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
  '.vue', '.svelte', '.astro', '.mdx',
])

/**
 * Check if a package has install scripts (postinstall, preinstall, install).
 * Packages with install scripts likely do something important at install time.
 */
function hasInstallScripts(projectPath: string, packageName: string): boolean {
  try {
    const pkgPath = join(projectPath, 'node_modules', ...packageName.split('/'), 'package.json')
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
    const scripts = pkg.scripts ?? {}
    return !!(scripts.postinstall || scripts.preinstall || scripts.install)
  } catch {
    return false
  }
}

/** Safety note included in every sweep result */
const SWEEP_NOTE = 'These are recommendations based on static analysis. Verify before removing — some packages may be used dynamically, in CI/CD pipelines, or by tools not detected by static scanning.'

/** Stylesheet extensions to scan for @use/@import of packages */
const STYLE_EXTENSIONS = new Set(['.css', '.scss', '.sass', '.less'])

/** Directories to always exclude from scanning */
const EXCLUDE_DIRS = new Set([
  'node_modules', 'dist', 'build', '.git', '.next', '.nuxt', '.svelte-kit',
  'coverage', 'out', '.output', '.cache', '.turbo', '__pycache__',
])

/**
 * Well-known config file patterns → the tool dependency they imply.
 * Key is a filename prefix/pattern, value is the package(s) it implies.
 */
const CONFIG_FILE_DEPS: Record<string, string[]> = {
  '.eslintrc': ['eslint'],
  'eslint.config': ['eslint'],
  '.prettierrc': ['prettier'],
  'prettier.config': ['prettier'],
  'jest.config': ['jest'],
  'vitest.config': ['vitest'],
  'babel.config': ['@babel/core'],
  '.babelrc': ['@babel/core'],
  'tsconfig': ['typescript'],
  'tailwind.config': ['tailwindcss'],
  'postcss.config': ['postcss'],
  'webpack.config': ['webpack'],
  'rollup.config': ['rollup'],
  'vite.config': ['vite'],
  'next.config': ['next'],
  'nuxt.config': ['nuxt'],
  'svelte.config': ['svelte'],
  '.swcrc': ['@swc/core'],
  '.mocharc': ['mocha'],
  'cypress.config': ['cypress'],
  'playwright.config': ['playwright', '@playwright/test'],
  '.storybook': ['storybook'],
  'turbo.json': ['turbo'],
  'nx.json': ['nx'],
  'lerna.json': ['lerna'],
}

/**
 * Normalize a module specifier to a package name.
 * `@scope/pkg/sub/path` → `@scope/pkg`
 * `pkg/sub/path` → `pkg`
 * `pkg` → `pkg`
 */
export function normalizeToPackageName(specifier: string): string {
  if (specifier.startsWith('@')) {
    // Scoped: @scope/pkg/...
    const parts = specifier.split('/')
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`
    return specifier
  }
  // Unscoped: pkg/...
  return specifier.split('/')[0]
}

/**
 * Extract package names from import/require/re-export statements in source code.
 * Returns a Set of normalized package names (excludes relative imports).
 */
export function extractImports(source: string): Set<string> {
  const packages = new Set<string>()

  // ES static imports: import ... from 'pkg' / import 'pkg'
  const esImport = /import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"./][^'"]*)['"]/g
  // Dynamic imports: import('pkg')
  const dynImport = /import\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g
  // CommonJS: require('pkg')
  const cjsRequire = /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g
  // Re-exports: export ... from 'pkg'
  const reExport = /export\s+[\s\S]*?\s+from\s+['"]([^'"./][^'"]*)['"]/g
  // require.resolve('pkg') — used to locate packages without importing
  const requireResolve = /require\.resolve\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g
  // jest.mock('pkg'), jest.requireActual('pkg'), jest.unmock('pkg')
  const jestMock = /jest\.(?:mock|requireActual|unmock)\s*\(\s*['"]([^'"./][^'"]*)['"]/g
  // TypeScript module augmentation: declare module 'pkg'
  const declareModule = /declare\s+module\s+['"]([^'"./][^'"]*)['"]/g

  for (const pattern of [esImport, dynImport, cjsRequire, reExport, requireResolve, jestMock, declareModule]) {
    let match: RegExpExecArray | null
    while ((match = pattern.exec(source)) !== null) {
      const specifier = match[1]
      // Skip node: built-in modules
      if (specifier.startsWith('node:')) continue
      packages.add(normalizeToPackageName(specifier))
    }
  }

  return packages
}

/**
 * Recursively collect source files matching the given extensions.
 * Excludes directories in the exclude set.
 */
export function collectSourceFiles(
  dir: string,
  extensions: Set<string> = SOURCE_EXTENSIONS,
  excludeDirs: Set<string> = EXCLUDE_DIRS,
): string[] {
  const files: string[] = []

  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return files
  }

  for (const entry of entries) {
    if (excludeDirs.has(entry)) continue

    const fullPath = join(dir, entry)
    let stat
    try {
      stat = statSync(fullPath)
    } catch {
      continue
    }

    if (stat.isDirectory()) {
      files.push(...collectSourceFiles(fullPath, extensions, excludeDirs))
    } else if (stat.isFile() && extensions.has(extname(entry))) {
      files.push(fullPath)
    }
  }

  return files
}

/**
 * Check config files in the project root for tool-dependency references.
 * Returns a map of package name → usage reason.
 */
export function findConfigDependencies(projectPath: string): Map<string, DepUsageReason> {
  const configDeps = new Map<string, DepUsageReason>()

  let rootEntries: string[]
  try {
    rootEntries = readdirSync(projectPath)
  } catch {
    return configDeps
  }

  for (const entry of rootEntries) {
    for (const [pattern, deps] of Object.entries(CONFIG_FILE_DEPS)) {
      if (entry.startsWith(pattern) || entry === pattern) {
        for (const dep of deps) {
          configDeps.set(dep, 'config-referenced')
        }
      }
    }

    // Scan config file content for plugin references
    if (entry.match(/eslint\.config|\.eslintrc/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, 'eslint-plugin-', 'eslint-config-', '@typescript-eslint/')
    }
    if (entry.match(/babel\.config|\.babelrc/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, '@babel/plugin-', '@babel/preset-', 'babel-plugin-', 'babel-preset-')
    }
    if (entry.match(/jest\.config/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, 'jest-', 'ts-jest', 'babel-jest', '@jest/')
    }
    if (entry.match(/tailwind\.config/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, '@tailwindcss/', 'tailwindcss-')
    }
    if (entry.match(/postcss\.config/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, 'postcss-', 'autoprefixer', 'cssnano')
    }
    if (entry.match(/webpack\.config/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, '-loader', '-plugin', 'webpack-')
    }
    if (entry.match(/vite\.config|rollup\.config/)) {
      scanConfigForPlugins(join(projectPath, entry), configDeps, '@vitejs/', 'vite-plugin-', '@rollup/', 'rollup-plugin-')
    }
  }

  return configDeps
}

/**
 * Scan a config file for plugin name references.
 */
function scanConfigForPlugins(
  filePath: string,
  configDeps: Map<string, DepUsageReason>,
  ...prefixes: string[]
): void {
  try {
    const content = readFileSync(filePath, 'utf-8')
    // Extract all string literals from the file
    const strings = content.match(/['"]([^'"]+)['"]/g) ?? []
    for (const str of strings) {
      const value = str.slice(1, -1) // Remove quotes
      for (const prefix of prefixes) {
        // Match: starts with prefix, ends with suffix, or equals prefix without trailing dash
        if (value.startsWith(prefix) || value.endsWith(prefix) || value === prefix.replace(/-$/, '')) {
          configDeps.set(value, 'config-referenced')
        }
      }
      // Also catch scoped packages referenced as strings in configs (e.g., "@scope/plugin")
      if (value.startsWith('@') && value.includes('/')) {
        configDeps.set(value, 'config-referenced')
      }
    }
  } catch {
    // Config file not readable, skip
  }
}

/**
 * Check npm scripts in package.json for binary references.
 * Returns a map of package name → usage reason.
 */
export function findScriptDependencies(
  scripts: Record<string, string>,
  projectPath: string,
): Map<string, DepUsageReason> {
  const scriptDeps = new Map<string, DepUsageReason>()

  // Build a map of binary name → package name from node_modules/.bin
  const binMap = new Map<string, string>()
  const nmPath = join(projectPath, 'node_modules')

  if (existsSync(nmPath)) {
    try {
      const topLevelDeps = readdirSync(nmPath)
      for (const dep of topLevelDeps) {
        if (dep.startsWith('.')) continue
        if (dep.startsWith('@')) {
          // Scoped packages
          try {
            const scopedDeps = readdirSync(join(nmPath, dep))
            for (const scopedDep of scopedDeps) {
              readBinFromPackage(join(nmPath, dep, scopedDep), `${dep}/${scopedDep}`, binMap)
            }
          } catch { /* skip */ }
        } else {
          readBinFromPackage(join(nmPath, dep), dep, binMap)
        }
      }
    } catch { /* skip */ }
  }

  // Check each script value for binary references and --require/--loader flags
  for (const scriptValue of Object.values(scripts)) {
    const tokens = scriptValue.split(/[\s;&|]+/)
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]
      const cleanToken = token.replace(/^(?:npx|pnpx|yarn|bunx)\s+/, '')
      // Check against binary map
      const cleanMatch = binMap.get(cleanToken)
      if (cleanMatch) {
        scriptDeps.set(cleanMatch, 'npm-script')
      }
      // Also check if token matches a dependency name directly
      const tokenMatch = binMap.get(token)
      if (tokenMatch) {
        scriptDeps.set(tokenMatch, 'npm-script')
      }
      // Detect --require <pkg> and --loader <pkg> patterns (node flags)
      if ((token === '--require' || token === '-r' || token === '--loader' || token === '--import') && i + 1 < tokens.length) {
        const nextToken = tokens[i + 1]
        if (nextToken && !nextToken.startsWith('-') && !nextToken.startsWith('.') && !nextToken.startsWith('/')) {
          scriptDeps.set(normalizeToPackageName(nextToken), 'npm-script')
        }
      }
      // Detect --require=pkg (equals form)
      const requireMatch = token.match(/^(?:--require|-r|--loader|--import)=(.+)$/)
      if (requireMatch && requireMatch[1] && !requireMatch[1].startsWith('.') && !requireMatch[1].startsWith('/')) {
        scriptDeps.set(normalizeToPackageName(requireMatch[1]), 'npm-script')
      }
    }
  }

  return scriptDeps
}

/**
 * Read the `bin` field from a package's package.json and add to the bin map.
 */
function readBinFromPackage(
  pkgDir: string,
  pkgName: string,
  binMap: Map<string, string>,
): void {
  try {
    const pkgJson = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf-8'))
    if (typeof pkgJson.bin === 'string') {
      // Single binary, named after the package
      const shortName = pkgName.includes('/') ? pkgName.split('/')[1] : pkgName
      binMap.set(shortName, pkgName)
    } else if (typeof pkgJson.bin === 'object' && pkgJson.bin !== null) {
      for (const binName of Object.keys(pkgJson.bin)) {
        binMap.set(binName, pkgName)
      }
    }
  } catch { /* skip */ }
}

/**
 * Estimate the installed size of a package in KB.
 * Does a shallow directory size estimation (not recursive into node_modules).
 */
export function estimatePackageSize(projectPath: string, packageName: string): number | null {
  const pkgDir = join(projectPath, 'node_modules', ...packageName.split('/'))
  if (!existsSync(pkgDir)) return null

  try {
    let totalBytes = 0
    const entries = readdirSync(pkgDir)
    for (const entry of entries) {
      if (entry === 'node_modules') continue
      try {
        const stat = statSync(join(pkgDir, entry))
        if (stat.isFile()) {
          totalBytes += stat.size
        }
      } catch { /* skip */ }
    }
    return Math.round(totalBytes / 1024)
  } catch {
    return null
  }
}

/**
 * Extract package names from stylesheet @use/@import statements.
 * Handles SCSS @use 'pkg', @import 'pkg', and Less @import 'pkg'.
 */
export function extractStyleImports(source: string): Set<string> {
  const packages = new Set<string>()
  // SCSS @use 'package' / @import 'package' (non-relative only)
  const atUse = /@use\s+['"]([^'"./~][^'"]*)['"]/g
  const atImport = /@import\s+['"]([^'"./~][^'"]*)['"]/g

  for (const pattern of [atUse, atImport]) {
    let match: RegExpExecArray | null
    while ((match = pattern.exec(source)) !== null) {
      const specifier = match[1]
      // Skip sass built-ins like 'sass:math'
      if (specifier.startsWith('sass:')) continue
      packages.add(normalizeToPackageName(specifier))
    }
  }
  return packages
}

/**
 * Find packages that are required as peer dependencies by other installed packages.
 * If package A has peerDependencies: { B: "^1.0" }, and both A and B are in
 * the project's deps, then B is considered "used" via peer-dep.
 */
function findPeerDependencyUsers(projectPath: string, depNames: string[]): Set<string> {
  const peerUsers = new Set<string>()
  const nmPath = join(projectPath, 'node_modules')
  if (!existsSync(nmPath)) return peerUsers

  for (const depName of depNames) {
    try {
      const depPkgPath = join(nmPath, ...depName.split('/'), 'package.json')
      const depPkg = JSON.parse(readFileSync(depPkgPath, 'utf-8'))
      const peerDeps = depPkg.peerDependencies as Record<string, string> | undefined
      if (peerDeps) {
        for (const peerName of Object.keys(peerDeps)) {
          if (depNames.includes(peerName)) {
            peerUsers.add(peerName)
          }
        }
      }
    } catch { /* package not installed or not readable */ }
  }

  return peerUsers
}

/**
 * In monorepos, scan workspace package.json files for dependency references.
 * This prevents marking a root dep as "unused" when a workspace uses it.
 */
function scanWorkspaceImports(
  projectPath: string,
  workspaces: string[] | { packages: string[] },
): Set<string> {
  const wsImports = new Set<string>()
  const patterns = Array.isArray(workspaces) ? workspaces : (workspaces.packages ?? [])

  for (const pattern of patterns) {
    // Resolve simple glob patterns (e.g., "packages/*")
    const basePath = pattern.replace(/\*.*$/, '')
    const wsRoot = join(projectPath, basePath)

    if (!existsSync(wsRoot)) continue

    try {
      const entries = readdirSync(wsRoot)
      for (const entry of entries) {
        const wsPkgPath = join(wsRoot, entry, 'package.json')
        if (!existsSync(wsPkgPath)) continue

        try {
          const wsPkg = JSON.parse(readFileSync(wsPkgPath, 'utf-8'))
          const wsDeps = {
            ...(wsPkg.dependencies ?? {}),
            ...(wsPkg.devDependencies ?? {}),
            ...(wsPkg.peerDependencies ?? {}),
          } as Record<string, string>

          for (const dep of Object.keys(wsDeps)) {
            wsImports.add(dep)
          }
        } catch { /* skip unreadable workspace package.json */ }
      }
    } catch { /* skip unreadable directory */ }
  }

  return wsImports
}

/**
 * Detect phantom dependencies: packages installed in node_modules
 * but not declared in package.json dependencies.
 */
export function detectPhantomDeps(
  projectPath: string,
  declaredDeps: string[],
): PhantomDep[] {
  const nmPath = join(projectPath, 'node_modules')
  if (!existsSync(nmPath)) return []

  const phantoms: PhantomDep[] = []
  const declaredSet = new Set(declaredDeps)

  try {
    const entries = readdirSync(nmPath)
    for (const entry of entries) {
      // Skip hidden files and directories (.package-lock.json, .cache, etc.)
      if (entry.startsWith('.')) continue
      // Skip the .bin directory
      if (entry === '.bin') continue

      if (entry.startsWith('@')) {
        // Scoped packages: read subdirectories
        try {
          const scopedEntries = readdirSync(join(nmPath, entry))
          for (const scopedEntry of scopedEntries) {
            const fullName = `${entry}/${scopedEntry}`
            if (!declaredSet.has(fullName)) {
              phantoms.push(createPhantomEntry(projectPath, fullName))
            }
          }
        } catch { /* skip unreadable scope directory */ }
      } else {
        if (!declaredSet.has(entry)) {
          phantoms.push(createPhantomEntry(projectPath, entry))
        }
      }
    }
  } catch { /* skip unreadable node_modules */ }

  return phantoms
}

function createPhantomEntry(projectPath: string, name: string): PhantomDep {
  let version: string | null = null
  try {
    const pkgPath = join(projectPath, 'node_modules', ...name.split('/'), 'package.json')
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
    version = pkg.version ?? null
  } catch { /* skip */ }

  return {
    name,
    version,
    estimatedSizeKB: estimatePackageSize(projectPath, name),
    reason: 'Installed in node_modules but not declared in package.json',
  }
}

/**
 * Detect unused dependencies in a project.
 * Purely filesystem-based — no network calls.
 */
export async function sweep(
  projectPath: string,
  options: SweepOptions = {},
): Promise<SweepResult> {
  const absPath = resolve(projectPath)
  const warnings: string[] = []

  // Step 1: Read package.json
  const pkgJsonPath = join(absPath, 'package.json')
  if (!existsSync(pkgJsonPath)) {
    return {
      projectPath: absPath,
      totalDependencies: 0,
      unused: [],
      maybeUnused: [],
      used: 0,
      estimatedSavingsKB: 0,
      scannedFiles: 0,
      warnings: ['No package.json found at project root'],
      note: SWEEP_NOTE,
    }
  }

  let pkgJson: Record<string, unknown>
  try {
    pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf-8'))
  } catch {
    return {
      projectPath: absPath,
      totalDependencies: 0,
      unused: [],
      maybeUnused: [],
      used: 0,
      estimatedSavingsKB: 0,
      scannedFiles: 0,
      warnings: ['Could not parse package.json'],
      note: SWEEP_NOTE,
    }
  }

  // Collect dependencies to check
  const deps = (pkgJson.dependencies ?? {}) as Record<string, string>
  const devDeps = options.includeDevDependencies
    ? (pkgJson.devDependencies ?? {}) as Record<string, string>
    : {}
  const allDeps = { ...deps, ...devDeps }
  const depNames = Object.keys(allDeps)

  if (depNames.length === 0) {
    return {
      projectPath: absPath,
      totalDependencies: 0,
      unused: [],
      maybeUnused: [],
      used: 0,
      estimatedSavingsKB: 0,
      scannedFiles: 0,
      warnings: [],
      note: SWEEP_NOTE,
    }
  }

  // Warn about monorepos
  if (pkgJson.workspaces) {
    warnings.push('Monorepo detected (workspaces). Consider running sweep per workspace for accurate results.')
  }

  // Step 2: Scan source files for imports
  const excludeDirs = new Set([...EXCLUDE_DIRS, ...(options.excludePatterns ?? [])])
  const sourceFiles = collectSourceFiles(absPath, SOURCE_EXTENSIONS, excludeDirs)
  const importedPackages = new Set<string>()

  for (const file of sourceFiles) {
    try {
      const content = readFileSync(file, 'utf-8')
      const imports = extractImports(content)
      for (const pkg of imports) {
        importedPackages.add(pkg)
      }
    } catch {
      warnings.push(`Could not read: ${file}`)
    }
  }

  // Step 2b: Scan stylesheet files for @use/@import of packages
  const styleFiles = collectSourceFiles(absPath, STYLE_EXTENSIONS, excludeDirs)
  for (const file of styleFiles) {
    try {
      const content = readFileSync(file, 'utf-8')
      const styleImports = extractStyleImports(content)
      for (const pkg of styleImports) {
        importedPackages.add(pkg)
      }
    } catch {
      warnings.push(`Could not read: ${file}`)
    }
  }

  // Step 3: Check config files
  const configDeps = findConfigDependencies(absPath)

  // Step 4: Check npm scripts
  const scripts = (pkgJson.scripts ?? {}) as Record<string, string>
  const scriptDeps = findScriptDependencies(scripts, absPath)

  // Step 5: Check peer dependencies — if package A needs B as peerDep, B is "used"
  const peerDepUsers = findPeerDependencyUsers(absPath, depNames)

  // Step 6: Scan workspace siblings if monorepo detected (npm/yarn workspaces or pnpm)
  let workspaceImports = new Set<string>()
  if (pkgJson.workspaces) {
    workspaceImports = scanWorkspaceImports(absPath, pkgJson.workspaces as string[] | { packages: string[] })
  } else {
    // Check for pnpm-workspace.yaml
    const pnpmWsPath = join(absPath, 'pnpm-workspace.yaml')
    if (existsSync(pnpmWsPath)) {
      try {
        const pnpmContent = readFileSync(pnpmWsPath, 'utf-8')
        // Simple YAML parsing for packages list: "  - 'packages/*'"
        const pnpmPatterns: string[] = []
        const lines = pnpmContent.split('\n')
        for (const line of lines) {
          const match = line.match(/^\s*-\s+['"]?([^'"#\n]+)['"]?\s*$/)
          if (match) pnpmPatterns.push(match[1].trim())
        }
        if (pnpmPatterns.length > 0) {
          workspaceImports = scanWorkspaceImports(absPath, pnpmPatterns)
          warnings.push('Monorepo detected (pnpm workspaces). Consider running sweep per workspace for accurate results.')
        }
      } catch { /* skip unreadable pnpm-workspace.yaml */ }
    }
  }

  // Step 7: Classify each dependency
  const unused: SweepDepResult[] = []
  const maybeUnused: SweepDepResult[] = []
  let usedCount = 0

  for (const name of depNames) {
    const reasons: DepUsageReason[] = []
    const version = allDeps[name] ?? 'unknown'

    // Check imports
    if (importedPackages.has(name)) {
      reasons.push('imported')
    }

    // Check config files
    if (configDeps.has(name)) {
      reasons.push('config-referenced')
    }

    // Check npm scripts
    if (scriptDeps.has(name)) {
      reasons.push('npm-script')
    }

    // Handle @types/* packages
    if (name.startsWith('@types/')) {
      const runtimeName = name.replace('@types/', '').replace('__', '/')
      if (importedPackages.has(runtimeName) || depNames.includes(runtimeName)) {
        reasons.push('types-only')
      }
    }

    // Check peer dependencies — if another installed package needs this as peerDep
    if (peerDepUsers.has(name)) {
      reasons.push('peer-dep')
    }

    // Check workspace imports — if another workspace package imports this
    if (workspaceImports.has(name)) {
      reasons.push('imported')
    }

    // Check if this is a well-known config-only tool not caught by file patterns
    // (e.g., typescript is referenced via tsconfig.json)
    if (reasons.length === 0) {
      for (const [, toolDeps] of Object.entries(CONFIG_FILE_DEPS)) {
        if (toolDeps.includes(name) && configDeps.has(name)) {
          reasons.push('config-referenced')
        }
      }
    }

    // Classify
    if (reasons.length > 0) {
      usedCount++
    } else {
      const sizeKB = estimatePackageSize(absPath, name)
      const depResult: SweepDepResult = {
        name,
        version,
        status: 'unused',
        reasons: [],
        estimatedSizeKB: sizeKB,
      }

      // Conservative classification — when in doubt, use maybe-unused.
      // We only say "unused" when we have high confidence.
      const shouldBeCautious =
        // devDependency — could be used by a config/tool we don't recognize
        (devDeps[name] && !deps[name]) ||
        // No node_modules — can't verify peer deps or bin scripts
        !existsSync(join(absPath, 'node_modules')) ||
        // Scoped packages used as plugins are hard to trace
        name.startsWith('@') ||
        // Packages with install scripts likely do something important
        hasInstallScripts(absPath, name)

      if (shouldBeCautious) {
        depResult.status = 'maybe-unused'
        maybeUnused.push(depResult)
      } else {
        unused.push(depResult)
      }
    }
  }

  // Calculate estimated savings
  const estimatedSavingsKB = unused.reduce((sum, dep) => sum + (dep.estimatedSizeKB ?? 0), 0)

  // Detect phantom dependencies (installed but not declared)
  const phantomDeps = detectPhantomDeps(absPath, depNames)

  return {
    projectPath: absPath,
    totalDependencies: depNames.length,
    unused,
    maybeUnused,
    used: usedCount,
    estimatedSavingsKB,
    scannedFiles: sourceFiles.length + styleFiles.length,
    warnings,
    phantomDeps: phantomDeps.length > 0 ? phantomDeps : undefined,
    note: SWEEP_NOTE,
  }
}
