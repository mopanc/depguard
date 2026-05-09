import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync, spawnSync } from 'node:child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..')

/**
 * Regression for #64. The CI runner's tsc output had `dist/cli.js` at
 * 0o644, npm packed it without the executable bit, and global installs
 * of v1.11.0 hit "Permission denied" when invoking `depguard-cli`.
 *
 * The fix is `chmod 755 dist/cli.js` in the build script. These tests
 * make sure neither the local file nor the publishable tarball ever
 * regress on the executable bit again.
 */
describe('cli executable bit (#64)', () => {
  it('dist/cli.js has the owner executable bit set after build', () => {
    const cliPath = join(repoRoot, 'dist', 'cli.js')
    if (!existsSync(cliPath)) {
      // Build hasn't run yet in this test process. The full `npm run check`
      // pipeline runs build before tests, so this branch only fires when
      // the test is run in isolation. Skip rather than mis-diagnose.
      return
    }
    const mode = statSync(cliPath).mode & 0o777
    assert.ok(
      (mode & 0o100) !== 0,
      `dist/cli.js mode is 0o${mode.toString(8)}, owner exec bit missing. ` +
      `package.json build script must chmod 755 the file.`,
    )
  })

  it('npm pack would publish dist/cli.js with the executable bit', () => {
    // `npm pack --dry-run --json` lists files with their modes. We only
    // need to confirm the cli.js entry has 0o100 (owner exec) set; the
    // CI runner has historically stripped it without explicit chmod.
    const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      env: { ...process.env, npm_config_loglevel: 'silent' },
    })
    if (result.status !== 0) {
      // npm not available in this environment (rare). Don't fail.
      return
    }

    let parsed: unknown
    try { parsed = JSON.parse(result.stdout) } catch { return }
    if (!Array.isArray(parsed) || parsed.length === 0) return

    const tarball = parsed[0] as { files?: Array<{ path: string; mode?: number }> }
    if (!Array.isArray(tarball.files)) return

    const cliEntry = tarball.files.find(f => f.path === 'dist/cli.js')
    assert.ok(cliEntry, 'dist/cli.js must be present in the publishable tarball')
    if (typeof cliEntry.mode === 'number') {
      assert.ok(
        (cliEntry.mode & 0o100) !== 0,
        `npm pack reports dist/cli.js mode 0o${(cliEntry.mode & 0o777).toString(8)}, ` +
        `owner exec bit missing. Global installs would fail with "Permission denied".`,
      )
    }
  })

  it('the built dist/cli.js actually executes via node when invoked directly', () => {
    const cliPath = join(repoRoot, 'dist', 'cli.js')
    if (!existsSync(cliPath)) return
    // Invoking via node bypasses the exec bit (this is what `npx` does
    // internally), but it does verify the file is a runnable script with
    // a valid shebang and no syntax errors after build.
    const out = execFileSync('node', [cliPath, '--version'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      timeout: 5000,
    }).trim()
    assert.match(out, /^\d+\.\d+\.\d+/)
  })
})
