import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'

export const chainIds = {
      1: 'mainnet',
  17000: 'holesky'
}

export const genesisForkVersion = {
      1: Buffer.from('00000000', 'hex'),
  17000: Buffer.from('01017000', 'hex')
}

export const capellaForkVersion = {
      1: Buffer.from('03000000', 'hex'),
  17000: Buffer.from('04017000', 'hex')
}

export const genesisValidatorRoot = {
      1: Buffer.from('4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95', 'hex'),
  17000: Buffer.from('9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1', 'hex')
}

export const addressRe = '0x[0-9a-f]{40}'
export const addressRegExp = new RegExp(addressRe)

export const readJSONL = (path) =>
  readFileSync(path, 'utf8').trimEnd().split('\n').map(JSON.parse)

// ERC-2334
const purpose = 12381
const coinType = 3600
export const pathsFromIndex = index => {
  const prefix = `m/${purpose}/${coinType}/${index}`
  const withdrawal = `${prefix}/0`
  const signing = `${withdrawal}/0`
  return {withdrawal, signing}
}

export const errorPrefix = 'error: '

export const prv = (command, {chainId, address, path, password}, input) => {
  const lines = []
  lines.push(`CHAINID = ${chainId}`)
  lines.push(`ADDRESS = ${address}`)
  lines.push(`COMMAND = ${command}`)
  if (path) lines.push(`KEYPATH = ${path}`)
  if (password) lines.push(`KEYPASS = ${password}`)
  if (input) lines.push(`MESSAGE = ${input}`)

  const [HOST, PORT] = process.env.PRV_HOST.split(':')

  // Gather connect info based on IS_DOCKER var.
  // If we're running in docker, the js files have been installed as a single binary file and `node` does not exist.
  const connect_app = process.env.IS_DOCKER ? 'nc' : 'node';
  const connect_params = process.env.IS_DOCKER ?  ['-w', 1, HOST, PORT] : ['sck.js'];
  console.debug(`lib | prv | Called with ${connect_app} using params:`, connect_params);
  const res = spawnSync(connect_app, connect_params, {
    input: lines.join('\n'),
    encoding: 'utf8',
    env: {HOST, PORT}
  })
  console.debug(`lib | prv | Got result: [${res.stdout}]`);

  const hasError = res.stdout.startsWith(errorPrefix);
  if (res.stderr.length === 0 && !hasError) {
    return res.stdout.trimEnd();
  } else if (hasError) {
    console.debug(`lib | prv | Returning error from stdout ${res.stdout}`);
    throw new Error(`500:${res.stdout.slice(errorPrefix.length)}`);
  } else {
    console.debug(`lib | prv | Returning error from stderr ${res.stderr}`);
    throw new Error(`500:prv failed: errors ${res.stderr}, stdout '${res.stdout}'`);
  }
}

const stateDir = process.env.STATE_DIR
const bareDir = `${stateDir}/bare`
export const workDir = `${stateDir}/work`

export const gitCheck = (args, cwd, expectedOutput, msg) => {
  console.debug(`lib | gitCheck | Called with: ${args} ${cwd}`);
  const res = spawnSync('git', args, {cwd})
  const checkOutput = typeof expectedOutput == 'string' ? (s => s === expectedOutput) : expectedOutput
  if (!(res.status === 0 && checkOutput(String(res.stdout))))
    throw new Error(msg + ` ${res.status} '${res.stdout}' '${res.stderr}'`)
}

export const ensureDirs = () => {
  console.debug("lib | ensureDirs | Called.");

  if (!existsSync(bareDir)) {
    gitCheck(['init', '--quiet', '--bare', '--initial-branch=main', 'bare'], stateDir, '', 'failed to create bare repository')
    gitCheck(['config', 'receive.denyNonFastForwards', 'true'], bareDir, '', 'failed to set denyNonFastForwards')
    gitCheck(['config', 'receive.denyDeletes', 'true'], bareDir, '', 'failed to set denyDeletes')
  }

  gitCheck(['rev-parse', '--is-bare-repository'], bareDir, 'true\n', 'bare is not a bare git repository')
  gitCheck(['config', 'receive.denyNonFastForwards'], bareDir, 'true\n', 'bare does not deny non-fast-forwards')
  gitCheck(['config', 'receive.denyDeletes'], bareDir, 'true\n', 'bare does not deny deletes')

  if (!existsSync(workDir)) {
    gitCheck(['clone', '--quiet', '--no-hardlinks', bareDir, workDir], stateDir, '', 'failed to clone work repository')
    gitCheck(['config', 'user.name', 'vrün'], workDir, '', 'failed to set user name')
    gitCheck(['config', 'user.email', 'db@vrün.com'], workDir, '', 'failed to set user email')
    gitCheck(['commit', '--quiet', '--allow-empty', '--message=init'], workDir, '', 'failed initial commit')
    gitCheck(['push', '--quiet'], workDir, '', 'failed initial push')
  }

  gitCheck(['status', '--porcelain'], workDir, '', 'work directory not clean')

  gitCheck(['rev-parse', '--abbrev-ref', '@{upstream}'], workDir, 'origin/main\n', 'work upstream not origin/main')

  gitCheck(['config', 'remote.origin.url'], workDir, `${bareDir}\n`, 'work remote is not bare')

  gitCheck(['config', 'user.name'], workDir, 'vrün\n', 'wrong user for work repository')
  gitCheck(['config', 'user.email'], workDir, 'db@vrün.com\n', 'wrong email for work repository')

  console.debug('lib | ensureDirs | Finished, all dirs are set up.');
}

const fastForwardRegExp = / \trefs\/heads\/main:refs\/heads\/main\t[0-9a-f]+\.\.[0-9a-f]+/
export const gitPush = (msg, cwd) => {
  console.debug("lib | gitPush | Called.");

  gitCheck(['commit', '--quiet', '--message', msg], cwd, '', 'failed to commit')
  gitCheck(['push', '--porcelain'], cwd,
    output => {
      const lines = output.trimEnd().split('\n')
      return (
        lines.length == 3 &&
        lines[0] == `To ${bareDir}` &&
        fastForwardRegExp.test(lines[1]) &&
        lines[2] == 'Done'
      )
    },
    'failed to push'
  )
}

// Log function to override existing console.<log type> functions
// allowing us to add a prefix with a datetime and severity level.
export const curDateTimeFormatted = () => {
  return new Date().toISOString();
};
const log_level = (process.env.LOG_LEVEL || 'warn').toLowerCase();

export const logFunction = (methodName) => {
  const originalLoggingMethod = console[methodName];
  console[methodName] = (firstArgument, ...otherArguments) => {
    if (
      (methodName === 'error') ||
      (methodName === 'warn' && ['warn', 'info', 'debug'].some((level) => level === log_level)) ||
      (methodName === 'info' && ['info', 'debug'].some((level) => level === log_level)) ||
      (methodName === 'debug' && log_level === 'debug')
    ) {
      const prefix = `${curDateTimeFormatted()} | ${methodName.toUpperCase()} | `;
      if (typeof firstArgument === 'string') {
        originalLoggingMethod(prefix + firstArgument, ...otherArguments);
      } else {
        originalLoggingMethod(prefix, firstArgument, ...otherArguments);
      }
    }
  };
};
