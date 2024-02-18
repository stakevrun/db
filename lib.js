import { spawnSync } from 'node:child_process'
import { existsSync, realpathSync } from 'node:fs'

export const chainIds = {
  1: 'mainnet',
  17000: 'holesky'
}

export const addressRe = '0x[0-9a-f]{40}'
export const addressRegExp = new RegExp(addressRe)

const stateDir = process.env.STATE_DIR
const bareDir = `${stateDir}/bare`
export const workDir = `${stateDir}/work`

export const gitCheck = (args, cwd, expectedOutput, msg) => {
  const res = spawnSync('git', args, {cwd})
  const checkOutput = typeof expectedOutput == 'string' ? (s => s === expectedOutput) : expectedOutput
  if (!(res.status === 0 && checkOutput(String(res.stdout))))
    throw new Error(msg + ` ${res.status} '${res.stdout}' '${res.stderr}'`)
}

export const gitPush = (msg, cwd) => {
  gitCheck(['commit', '--quiet', '--message', msg], cwd, '', 'failed to commit')
  gitCheck(['push', '--porcelain'], cwd,
    output => (output.startsWith('*') &&
               !output.trimEnd().includes('\n')),
    'failed to push'
  )
}

if (!existsSync(bareDir)) {
  gitCheck(['init', '--quiet', '--bare', '--initial-branch=main', 'bare'], stateDir, '', 'failed to create bare repository')
  gitCheck(['config', 'receive.denyNonFastForwards', 'true'], bareDir, '', 'failed to set denyNonFastForwards')
  gitCheck(['config', 'receive.denyDeletes', 'true'], bareDir, '', 'failed to set denyDeletes')
}

gitCheck(['rev-parse', '--is-bare-repository'], bareDir, 'true\n', 'bare is not a bare git repository')
gitCheck(['config', 'receive.denyNonFastForwards'], bareDir, 'true\n', 'bare does not deny non-fast-forwards')
gitCheck(['config', 'receive.denyDeletes'], bareDir, 'true\n', 'bare does not deny deletes')

const bareRealPath = realpathSync(bareDir)

if (!existsSync(workDir)) {
  gitCheck(['clone', '--quiet', '--no-hardlinks', bareDir, workDir], stateDir, '', 'failed to clone work repository')
  gitCheck(['config', 'user.name', 'vrün'], workDir, '', 'failed to set user name')
  gitCheck(['config', 'user.email', 'db@vrün.com'], workDir, '', 'failed to set user email')
  gitCheck(['commit', '--quiet', '--allow-empty', '--message=init'], workDir, '', 'failed initial commit')
  gitCheck(['push', '--quiet'], workDir, '', 'failed initial push')
}

gitCheck(['status', '--porcelain'], workDir, '', 'work directory not clean')

gitCheck(['rev-parse', '--abbrev-ref', '@{upstream}'], workDir, 'origin/main\n', 'work upstream not origin/main')

gitCheck(['config', 'remote.origin.url'], workDir,
  s => realpathSync(s.trim()) === bareRealPath,
  'work remote is not bare'
)

gitCheck(['config', 'user.name'], workDir, 'vrün\n', 'wrong user for work repository')
gitCheck(['config', 'user.email'], workDir, 'db@vrün.com\n', 'wrong email for work repository')
