import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRe, addressRegExp, readJSONL, pathsFromIndex,
         genesisForkVersion, genesisValidatorRoot, capellaForkVersion, prv } from './lib.js'
import { mkdirSync, existsSync, readdirSync, writeFileSync } from 'node:fs'
import fs from 'node:fs'
import net from 'node:net'
import { createServer } from 'node:http'
import { sha256 } from "ethereum-cryptography/sha256.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { hexToBytes, toHex, concatBytes } from "ethereum-cryptography/utils.js";

const port = (process.env.SRV_LISTEN_PORT || 8880)

const curDateTime = () => Intl.DateTimeFormat(
  'en-GB',
  { dateStyle: 'short', timeStyle: 'medium' }
).format(Date.now())

// Override stdout and stderr message output with time and type prefix
const log_level = (process.env.LOG_LEVEL || 'warn').toLowerCase();
['debug', 'info', 'warn', 'error'].map((methodName) => {
  const originalLoggingMethod = console[methodName];
  console[methodName] = (firstArgument, ...otherArguments) => {
    if (
      (methodName === 'error') ||
      (methodName === 'warn' && ['warn', 'info', 'debug'].some((level) => level === log_level)) ||
      (methodName === 'info' && ['info', 'debug'].some((level) => level === log_level)) ||
      (methodName === 'debug' && log_level === 'debug')
    ) {
      const prefix = `${curDateTime()} | ${methodName.toUpperCase()} | `;
      if (typeof firstArgument === 'string') {
        originalLoggingMethod(prefix + firstArgument, ...otherArguments);
      } else {
        originalLoggingMethod(prefix, firstArgument, ...otherArguments);
      }
    }
  };
});
process.setUncaughtExceptionCaptureCallback((e) => console.error(e.message + '\n' + e.stack))

ensureDirs()

// srv repository database layout:
// ${chainId}/a/${address} : JSON lines of signed acceptances of the terms of service
// ${chainId}/c/${address} : JSON lines of CreditAccount log entries
// ${chainId}/${address}/${pubkey} : JSON lines of log entries
//
// the log is an append-only record of user instructions
//
// log entries are the 'instruction' objects described below with the pubkey
// field removed and type and signature keys added.
//
// every change to the database is committed in work and pushed to bare
// if this succeeds we send back the successful HTTP response
// then we attempt to follow the instruction (except PUT requests are attempted
// before the response)

const pubkeyRe = `0x[0-9a-f]{96}`
const routesRegExp = new RegExp(`^/(?:` +
  `(?<health>health)|` +
  `(?<admins>admins)|` +
  `(?<declaration>declaration)|(?:` +
  `(?<chainId>[0-9]+)/(?:` +
    `(?<types>types)|` +
    `(?<address>${addressRe})/(?:` +
      `(?<nextindex>nextindex)|` +
      `(?<pubkey>pubkey)/(?<index>[0-9]+)|` +
      `(?<creditOrPubkey>(?:${pubkeyRe})|(?:credit))/(?<lengthOrLogs>(?:length)|(?:logs))|` +
      `(?<acceptance>acceptance)))` +
  `))$`
)

const getNextIndex = addressPath =>
  existsSync(addressPath) ?
    readdirSync(addressPath).length :
    null

const numberRegExp = /[0-9]+/
const hexStringRegExp = /0x[0-9a-fA-F]*/
const bytes32RegExp = /0x[0-9a-fA-F]{64}/
const structTypeRegExp = /(?<name>\w+)\((?<args>(?:\w+(?:\[\])? \w+(?:,\w+(?:\[\])? \w+)*)?)\)/

const MAX_STRING_LENGTH = 128

const encodeData = (data, encodedType) => {
  if (encodedType == 'string') {
    if (typeof data != 'string') throw new Error('not a string')
    if (data.length > MAX_STRING_LENGTH) throw new Error('string too long')
    return keccak256(Buffer.from(data))
  }
  else if (encodedType == 'bytes') {
    if (!hexStringRegExp.test(data))
      throw new Error('not a hexstring')
    return keccak256(hexToBytes(data))
  }
  else if (encodedType == 'bytes32') {
    if (!bytes32RegExp.test(data))
      throw new Error('not a bytes32 hexstring')
    return hexToBytes(data)
  }
  else if (['uint256','address','bool'].includes(encodedType)) {
    if (!['number','bigint','boolean','string'].includes(typeof data))
      throw new Error('not atomic')
    if ((typeof data == 'boolean' && encodedType != 'bool') ||
        (typeof data == 'string' && !['uint256','address'].includes(encodedType)) ||
        (['number','bigint'].includes(typeof data) && encodedType != 'uint256'))
      throw new Error('wrong type')
    if (typeof data == 'string' &&
        !(hexStringRegExp.test(data) ||
          encodedType == 'uint256' && numberRegExp.test(data)))
      throw new Error('not a hexstring')
    return hexToBytes(BigInt(data).toString(16).padStart(64, '0'))
  }
  else if (encodedType.endsWith('[]')) {
    const type = encodedType.slice(0, -2)
    const bytes = new Uint8Array(data.length * 32)
    data.forEach((x, i) => bytes.set(encodeData(x, type), i * 32))
    return keccak256(bytes)
  }
  else {
    const match = structTypeRegExp.exec(encodedType)
    if (!match) throw new Error('invalid encoded type')
    const args = match.groups.args.split(',').map(arg => arg.split(' '))
    const encodedData = new Uint8Array(args.length * 32)
    // only works when structs are not nested
    for (const [i, [type, key]] of args.entries())
      encodedData.set(encodeData(data[key], type), i * 32)
    return encodedData
  }
}

const hashStruct = (data, encodedType) => {
  const typeHash = keccak256(Buffer.from(encodedType))
  const encodedData = encodeData(data, encodedType)
  return keccak256(concatBytes(typeHash, encodedData))
}

const eip712Domain = chainId => ({name: 'vrün', version: '1', chainId})
const domainSeparators = new Map()
for (const chainId of Object.keys(chainIds)) {
  domainSeparators.set(chainId,
    hashStruct(
      eip712Domain(chainId),
      'EIP712Domain(string name,string version,uint256 chainId)'
    )
  )
}

const normaliseData = (data, args) => {
  const normalised = {}
  for (const arg of args) {
    const [type, key] = arg.split(' ')
    switch (type) {
      case 'bytes32':
      case 'address':
      case 'bytes':
        normalised[key] = data[key].toLowerCase()
        break
      case 'uint256':
        normalised[key] = BigInt(data[key]).toString()
        break
      case 'address[]':
      case 'bytes[]':
        normalised[key] = data[key].map(a => a.toLowerCase())
      case 'bool':
      case 'string':
      case 'string[]':
      default:
        normalised[key] = data[key]
    }
  }
  return normalised
}

const requiredDeclaration = 'I accept the terms of service specified at https://vrün.com/terms ' +
                            '(version: 20241008) (sha256sum: 9320acb47c90bf307a274187f45bdfa114a6d1c3ecd0a4d9d23dc80e5e2bffbf terms.md).'

const adminAddresses = [
  '0xB0De8cB8Dcc8c5382c4b7F3E978b491140B2bC55'.toLowerCase(), // gov.ramana.eth
]
// Add vrün fee server signer address provided through environment if set
if(process.env.FEE_SIGNER_ADDRESS) {
  console.debug(`Adding fee signing address ${process.env.FEE_SIGNER_ADDRESS} to admin addresses list.`)
  adminAddresses.push(process.env.FEE_SIGNER_ADDRESS.toLowerCase())
} else {
  console.warn(`No FEE_SIGNER_ADDRESS provided, the fee service will not be added to the admin addresses list.`)
}

const typesForPUT = new Map()
const typesForPOST = new Map()
const typesToRefresh = new Set()

typesForPUT.set('AcceptTermsOfService', 'string declaration')

typesForPUT.set('CreateKey', 'uint256 index')

typesForPOST.set('GetDepositData',
  'bytes pubkey,bytes32 withdrawalCredentials,uint256 amountGwei'
)

typesForPOST.set('GetPresignedExit',
  'bytes pubkey,uint256 validatorIndex,uint256 epoch'
)

typesForPOST.set('SetFeeRecipient',
  'uint256 timestamp,bytes[] pubkeys,address feeRecipient,string comment'
)
typesToRefresh.add('SetFeeRecipient')

typesForPOST.set('SetGraffiti',
  'uint256 timestamp,bytes[] pubkeys,string graffiti,string comment'
)
typesToRefresh.add('SetGraffiti')

typesForPOST.set('SetEnabled',
  'uint256 timestamp,bytes[] pubkeys,bool enabled,string comment'
)
typesToRefresh.add('SetEnabled')

typesForPOST.set('AddValidators',
  'uint256 timestamp,uint256 firstIndex,' +
  'uint256 amountGwei,address feeRecipient,string graffiti,' +
  'address[] withdrawalAddresses,string comment'
)
typesToRefresh.add('AddValidators')

typesForPOST.set('CreditAccount',
  'uint256 timestamp,address nodeAccount,'+
  'uint256 numDays,bool decreaseBalance,' +
  'uint256 tokenChainId,address tokenAddress,' +
  'bytes32 transactionHash,string comment'
)

const types = {}
const addType = (args, struct) => {
  types[struct] = args.split(',').map(s => {
    const [type, name] = s.split(' ')
    return {type, name}
  })
}
typesForPUT.forEach(addType)
typesForPOST.forEach(addType)

let refreshActorLock
let refreshedActorOnce
const actorFifo = (process.env.ACT_FIFO_DIR || '/run') + '/' + (process.env.ACT_FIFO_FILE || 'vrun-act.fifo')
const refreshActor = async () => {
  if (refreshActorLock) return
  refreshActorLock = true
  try {
    if (existsSync(actorFifo)) {
      console.debug("refreshActor() called.")

      // Using net.Socket to write to our stream so we won't run into blocking issues:
      // https://github.com/nodejs/node/issues/23220
      // Read write flag is required even if you only need to write because otherwise you get ENXIO https://linux.die.net/man/4/fifo
      // Non blocking flag is required to avoid blocking threads in the thread pool
      const fileHandle = await fs.promises.open(actorFifo, fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
      // readable: false avoids buffering reads from the pipe in memory
      const fifoStream = new net.Socket({ fd: fileHandle.fd, readable: false });

      // Write to fifo
      const shouldContinue = fifoStream.write('rf\n');
      // Backpressure if buffer is full
      if (!shouldContinue) {
        console.warn("Can't continue, draining fifoStream...")
        await once(fifoStream, 'drain');
      }

      // Be aware that if you close without waiting for drain you will have errors on next write from the Socket class
      await fileHandle.close();

      refreshedActorOnce = true

      console.debug("Refresh cmd sent.")
    } else {
      throw new Error("Can't access actor fifo.")
    }
  }
  finally {
    refreshActorLock = false
  }
}

const verifyEIP712 = ({body, domainSeparator, typeMap}) => {
  console.debug(`verifyEIP712 for domainSeparator [${domainSeparator}]`)

  if (!body) throw new Error('400:No data')
  const {type, data, signature, indices} = JSON.parse(body)

  console.debug({type, data, signature, indices})

  if (!(typeMap.has(type))) throw new Error('400:Invalid type')
  const args = typeMap.get(type)

  let sig = signature.startsWith('0x') ? signature.slice(2, -2) : signature.slice(0, -2)
  const v = parseInt(`0x${signature.slice(-2)}`) - 27
  if (sig.length != 2 * 64) throw new Error(`400:Invalid signature length ${sig.length}`)
  try { sig = secp256k1.Signature.fromCompact(sig).addRecoveryBit(v) }
  catch (e) { throw new Error(`400:Invalid signature: ${e.message}`) }

  let message
  try {
    let struct = hashStruct(data, `${type}(${args})`)
    message = concatBytes(Buffer.from('\x19\x01'), domainSeparator, struct)
  }
  catch (e) { throw new Error(`400:Invalid data: ${e.message}`) }

  const msgHash = keccak256(message)
  const sigPubkey = sig.recoverPublicKey(msgHash)
  const verified = secp256k1.verify(sig, msgHash, sigPubkey.toRawBytes())
  if (!verified) throw new Error(`400:Invalid signature`)
  const pubkeyForKeccak = sigPubkey.toRawBytes(false).slice(1)
  if (pubkeyForKeccak.length != 64) throw new Error(`500:Unexpected pubkey length ${toHex(pubkeyForKeccak)}`)
  const address = `0x${toHex(keccak256(pubkeyForKeccak).slice(-20))}`
  return {type, data: normaliseData(data, args.split(',')), address, signature, indices}
}

const addLogLine = (logPath, log) => {
  console.debug(`Adding new log line to path [${logPath}]`)
  console.debug(log)

  if (!logPath.startsWith(`${workDir}/`))
    throw new Error(`500:Unexpected workDir mismatch`)
  const repoLogPath = logPath.slice(workDir.length + 1)
  writeFileSync(logPath, `${JSON.stringify(log)}\n`, {flag: 'a'})
  gitCheck(['add', repoLogPath], workDir, '', `failed to log ${log.type}`)
  gitCheck(['diff', '--staged', '--numstat'], workDir,
    output => (
      !output.trimEnd().includes('\n') &&
      output.trimEnd().split(/\s+/).join() == `1,0,${repoLogPath}`
    ),
    `unexpected diff logging ${log.type}`
  )
  gitPush(log.type, workDir)
}

const merkleRoot = (leaves) => {
  const node = new Uint8Array(64)
  while (leaves.length > 1) {
    node.set(leaves.shift())
    node.set(leaves.shift(), 32)
    leaves.push(sha256(node))
  }
  return leaves.shift()
}

const uint64Root = (i) => {
  const bytes = new DataView(new ArrayBuffer(8))
  bytes.setBigUint64(0, BigInt(i), true)
  const padded = new Uint8Array(32)
  padded.set(new Uint8Array(bytes.buffer))
  return padded
}

const computeDomain = (type, forkVersionPrefix, genesisValidatorRoot) => {
  const domain = new Uint8Array(32)
  domain[0] = type
  const forkVersion = new Uint8Array(32)
  forkVersion.set(forkVersionPrefix)
  const forkDataRoot = merkleRoot([forkVersion, genesisValidatorRoot])
  domain.set(forkDataRoot.slice(0, 28), 4)
  return domain
}

const computeDepositData = ({amountGwei, pubkey, withdrawalCredentials, chainId, address, path}) => {
  const pubkeyBytes = hexToBytes(pubkey)
  const pubkeyBytesPadded = new Uint8Array(64)
  pubkeyBytesPadded.set(pubkeyBytes)
  const wcBytes = typeof withdrawalCredentials == 'string' ?
    hexToBytes(withdrawalCredentials) : withdrawalCredentials
  const amountRoot = uint64Root(amountGwei)
  const pubkeyRoot = merkleRoot(
    [pubkeyBytesPadded.slice(0, 32), pubkeyBytesPadded.slice(32)]
  )
  const zero32 = new Uint8Array(32)
  const depositMessageRoot = merkleRoot(
    [pubkeyRoot, wcBytes, amountRoot, zero32]
  )

  const domain = computeDomain(3, genesisForkVersion[chainId], zero32)
  const signingRoot = merkleRoot([depositMessageRoot, domain])
  const signature = prv('sign', {chainId, address, path}, `0x${toHex(signingRoot)}`)
  const signatureBytes = hexToBytes(signature)

  const signatureRoot = merkleRoot([
    signatureBytes.slice(0, 32), signatureBytes.slice(32, 64),
    signatureBytes.slice(64), zero32
  ])

  const depositDataRootBytes = merkleRoot(
    [pubkeyRoot, wcBytes, amountRoot, signatureRoot]
  )
  const depositDataRoot = `0x${toHex(depositDataRootBytes)}`
  return {depositDataRoot, signature}
}

const computePresignedExit = ({validatorIndex, epoch, chainId, address, path}) => {
  const domain = computeDomain(4, capellaForkVersion[chainId], genesisValidatorRoot[chainId])
  const voluntaryExitRoot = merkleRoot([uint64Root(epoch), uint64Root(validatorIndex)])
  const signingRoot = merkleRoot([voluntaryExitRoot, domain])
  const signature = prv('sign', {chainId, address, path}, `0x${toHex(signingRoot)}`)
  return {signature, message: {epoch, validator_index: validatorIndex}}
}

const getAddressCreditPath = (chainId, address, createDirIfnotExists) => {
  const creditDir = `${workDir}/${chainId}/c`
  const creditPath = `${creditDir}/${address}`
  const existing = existsSync(creditDir)
  if (!existing && createDirIfnotExists) {
    console.info(`Credit dir does not exist yet creating...`)
    mkdirSync(creditDir, {recursive: true})
  } else if(!existing) {
    return undefined
  }

  return creditPath
}

const validateAddressAcceptance = (chainId, address) => {
  const acceptanceDir = `${workDir}/${chainId}/a`
  const acceptancePath = `${acceptanceDir}/${address}`
  if (existsSync(acceptancePath)) {
    const {timestamp, declaration, signature} = readJSONL(acceptancePath).at(-1)
    if (declaration === requiredDeclaration) {
      return {acceptancePath, acceptance: {timestamp, declaration, signature}}
    }
  }

  return {acceptancePath, acceptance: undefined}
}

const validateTimestamp = (timestamp) => {
  const timestampInt = parseInt(timestamp)
  const now = Math.round(Date.now() / 1000)
  if (now < timestampInt) {
    console.error(`Provided timestamp [${timestampInt}] seems to be greater than now() [${now}].`)
    throw new Error(`400:Timestamp in the future`)
  }
  return timestampInt
}

const validateTSNotTooEarly = (timestamp, logs) => {
  if(logs.length) {
    const lastLog = logs.at(-1)
    const logTimestampInt = parseInt(lastLog.timestamp)
    const timestampInt = parseInt(timestamp)

    if(!(logTimestampInt <= timestampInt)) {
      console.error(`Provided timestamp [${timestampInt}] seems to be earlier than last log entry timestamp [${logTimestampInt}].`)
      throw new Error(`400:Timestamp too early`)
    }
  }
}

const allowedMethods = 'GET,POST,PUT'

createServer((req, res) => {
  const resHeaders = { }

  function handler(e) {
    let [code, body] = e.message.split(':', 2)
    if (body) body += e.message.slice(code.length + 1 + body.length)
    const statusCode = parseInt(code) || 500
    if (!body && statusCode == 500) body = e.message
    if (body) {
      if (statusCode == 405) {
        resHeaders['Allow'] = allowedMethods
        res.writeHead(statusCode, headers).end()
      }
      else {
        resHeaders['Content-Type'] = 'text/plain'
        resHeaders['Content-Length'] = Buffer.byteLength(body)
        res.writeHead(statusCode, resHeaders)
        res.end(body)
      }
    }
    else {
      res.writeHead(statusCode, resHeaders).end()
    }
    console.warn(`${req.method} ${req.url} -> ${statusCode}: ${body || ''}`)
  }

  function finish(statusCode, body) {
    resHeaders['Content-Length'] = Buffer.byteLength(body)
    res.writeHead(statusCode, resHeaders)
    res.end(body)
    console.info(`${req.method} ${req.url} -> ${statusCode}: ${body}`)
  }

  try {
    resHeaders['Content-Type'] = 'application/json'
    const url = new URL(req.url, `http://${req.headers.host}`)
    const pathname = url.pathname.toLowerCase()
    if (['GET'].includes(req.method)) {
      const match = routesRegExp.exec(pathname)
      if (!match) throw new Error('404:Unknown route')
      if (match.groups.health === 'health') {
        let responseString = 'Pending...'
        if (refreshedActorOnce) responseString = 'Ready!'
        else {
          console.info("Running startup check...")
          refreshActor().then(() => {
            console.debug('Triggered act from health check.')
            if (refreshedActorOnce) responseString = 'Ready!'
          })
        }
        body = JSON.stringify(responseString)
        resHeaders['Content-Length'] = Buffer.byteLength(body)
        res.writeHead(200, resHeaders)
        return res.end(body)
      }
      if (match.groups.admins === 'admins')
        return finish(200, JSON.stringify(adminAddresses))
      if (match.groups.declaration === 'declaration')
        return finish(200, JSON.stringify(requiredDeclaration))
      const chainId = parseInt(match.groups.chainId)
      const chain = chainIds[chainId]
      if (!chain) throw new Error('404:Unknown chainId')
      if (match.groups.types === 'types')
        return finish(200, JSON.stringify({types, domain: eip712Domain(chainId)}))
      const address = match.groups.address
      const addressPath = `${workDir}/${chainId}/${address}`
      const creditPath = `${workDir}/${chainId}/c/${address}`
      if (match.groups.nextindex === 'nextindex') {
        finish(200, (+getNextIndex(addressPath)).toString())
      }
      else if (match.groups.acceptance === 'acceptance') {
        const {acceptancePath, acceptance} = validateAddressAcceptance(chainId, address);
        if(!acceptance) throw new Error(`404:Acceptance missing`)
        finish(200, JSON.stringify(acceptance))
      }
      else if (match.groups.pubkey === 'pubkey') {
        if (!existsSync(addressPath)) throw new Error('404:Unknown address')
        const index = parseInt(match.groups.index)
        if (!(0 <= index)) throw new Error('400:Invalid index')
        const {signing: path} = pathsFromIndex(index)
        const pubkey = prv('pubkey', {chainId, address, path})
        if (!existsSync(`${addressPath}/${pubkey}`)) throw new Error(`400:Unknown index`)
        finish(200, JSON.stringify(pubkey))
      }
      else {
        console.debug('handling GET for other route')
        const {acceptancePath, acceptance} = validateAddressAcceptance(chainId, address);
        if(!acceptance) {
          throw new Error('400:Unknown address or pubkey')
        }

        const creditRoute = match.groups.creditOrPubkey === 'credit'
        const logPath = creditRoute ? getAddressCreditPath(chainId, address, true) : `${addressPath}/${match.groups.creditOrPubkey}`
        const unfiltered = existsSync(logPath) ? readJSONL(logPath) : []
        const makeRe = x => new RegExp(url.searchParams.get(x) || '', 'i')
        const typeRe = makeRe('type')
        const commentRe = makeRe('comment')
        const hash = url.searchParams.get('hash')?.toLowerCase()
        const filter = creditRoute ?
          x => commentRe.test(x.comment) && (!hash || x.transactionHash === hash) :
          x => typeRe.test(x.type)
        const logs = unfiltered.filter(filter)

        if (match.groups.lengthOrLogs === 'length') {
          console.debug("Returning logs count")
          finish(200, logs.length.toString())
        }
        else if (match.groups.lengthOrLogs === 'logs') {
          console.debug("Returning filtered logs")
          const start = url.searchParams.get('start')
          const endInt = parseInt(url.searchParams.get('end'))
          const end = Number.isNaN(endInt) ? logs.length : endInt
          finish(200, JSON.stringify(logs.slice(start, end)))
        }
        else {
          throw new Error('404:Unexpected route')
        }
      }
    }
    else if (['PUT', 'POST'].includes(req.method)) {
      const pathParts = pathname.split('/')
      if (pathParts.length !== (req.method == 'PUT' ? 3 : 4)) throw new Error('404:Unknown route')
      const [, chainId, address, index] = pathParts
      if (!domainSeparators.has(chainId)) throw new Error('404:Unknown chainId')
      if (!addressRegExp.test(address)) throw new Error('404:Invalid address')
      if (typeof index !== 'undefined' && !numberRegExp.test(index) && index !== 'batch' && index !== 'credit') throw new Error('404:Invalid index')
      const [contentType, charset] = req.headers['content-type']?.split(';') || []
      if (contentType !== 'application/json')
        throw new Error('415:Accepts application/json only')
      if (charset && charset.trim().toLowerCase() !== 'charset=utf-8')
        throw new Error('415:Accepts charset=utf-8 only')
      let body = ''
      req.setEncoding('utf8')
      req.on('data', chunk => body += chunk)
      req.on('end', () => {
        try {
          const typeMap = req.method == 'PUT' ? typesForPUT : typesForPOST
          const domainSeparator = domainSeparators.get(chainId)
          const {type, data, address: sigAddress, signature, indices} = verifyEIP712({domainSeparator, body, typeMap})
          if ((index === 'credit') !== (type === 'CreditAccount')) throw new Error(`400:Credit route type mismatch`)
          const validSigAddresses = index === 'credit' ? adminAddresses : [address]
          if (!validSigAddresses.includes(sigAddress)) throw new Error(`400:Address mismatch: ${sigAddress}`)
          if (index === 'batch' && (!data.pubkeys || !indices || data.pubkeys.length !== indices.length))
            throw new Error(`400:Invalid indices/pubkeys`)
          const addressPath = `${workDir}/${chainId}/${address}`

          const {acceptancePath, acceptance} = validateAddressAcceptance(chainId, address);
          if(!acceptance && !(['AcceptTermsOfService', 'CreditAccount'].includes(type))) {
            throw new Error('400:Acceptance of terms of service missing')
          }

          if (type == 'AddValidators') {
            const firstIndex = parseInt(data.firstIndex)
            const nextIndex = getNextIndex(addressPath)
            if (!(firstIndex <= nextIndex)) throw new Error(`400:First index unknown or not next`)
            if (nextIndex === null) {
              const result = prv('generate', {chainId, address})
              if (result != 'created') throw new Error(`500:Unexpected generate result`)
              mkdirSync(addressPath, {recursive: true})
            }
            const newLogs = {}
            const depositDataByPubkey = {}
            const timestamp = validateTimestamp(data.timestamp)

            let index = firstIndex
            for (const withdrawalAddress of data.withdrawalAddresses) {
              const existing = index < nextIndex
              const {signing: path} = pathsFromIndex(index)
              const pubkey = prv('pubkey', {chainId, address, path})
              const logPath = `${addressPath}/${pubkey}`
              const newLogsForPubkey = []
              newLogs[logPath] = newLogsForPubkey
              if (!existing)
                newLogsForPubkey.push({type: 'CreateKey', timestamp: timestamp.toString(), index: index.toString()})
              const withdrawalCredentials = new Uint8Array(32)
              withdrawalCredentials[0] = 1
              withdrawalCredentials.set(hexToBytes(withdrawalAddress), 12)
              const depositData = computeDepositData({
                amountGwei: data.amountGwei, pubkey, withdrawalCredentials, chainId, address, path
              })
              depositDataByPubkey[pubkey] = depositData
              const logs = existing ? readJSONL(logPath) : []
              validateTSNotTooEarly(timestamp, logs)

              for (const [type, value] of [['SetFeeRecipient', data.feeRecipient],
                                           ['SetGraffiti', data.graffiti],
                                           ['SetEnabled', true]]) {
                const keyCap = type.slice(3)
                const key = `${keyCap.slice(0, 1).toLowerCase()}${keyCap.slice(1)}`
                const lastLog = logs.toReversed().find(({type: logType}) => logType == type)
                if (lastLog?.[key] === value) throw new Error(`400:Setting unchanged`)
                newLogsForPubkey.push({type, timestamp: timestamp.toString(), [key]: value})
              }
            }
            for (const [logPath, logs] of Object.entries(newLogs)) {
              writeFileSync(logPath, logs.map(log => `${JSON.stringify(log)}\n`).join(''), {flag: 'a'})
              gitCheck(['add', logPath], workDir, '', `failed to add logs`)
            }
            const lineRegExp = new RegExp(`[45]\\s+0\\s+${chainId}/${address}/(?<pubkey>${pubkeyRe})`)
            gitCheck(['diff', '--staged', '--numstat'], workDir,
              output => {
                const lines = output.trimEnd().split('\n')
                if (lines.length != data.withdrawalAddresses.length) return false
                const pubkeys = lines.map(line => lineRegExp.exec(line)?.groups.pubkey)
                return (Object.keys(depositDataByPubkey).every(x => pubkeys.includes(x)) &&
                        pubkeys.every(x => x in depositDataByPubkey))
              },
              `unexpected diff adding logs`
            )
            gitPush(type, workDir)
            finish(201, JSON.stringify(depositDataByPubkey))
          }
          else if (type == 'AcceptTermsOfService') {
            if (data.declaration !== requiredDeclaration)
              throw new Error('400:Invalid declaration')

            if (!acceptance) mkdirSync(`${workDir}/${chainId}/a`, {recursive: true})

            const existing = acceptance && (acceptance.declaration === data.declaration)
            if (!existing) {
              const timestamp = Math.floor(Date.now() / 1000).toString()
              addLogLine(acceptancePath, {type, timestamp, ...data, signature})
            }
            const statusCode = existing ? 200 : 201
            finish(statusCode, '')
          }
          else if (type == 'CreditAccount') {
            const creditPath = getAddressCreditPath(chainId, address, true)
            const existing = existsSync(creditPath)
            const logs = existing ? readJSONL(creditPath) : []
            const timestamp = validateTimestamp(data.timestamp)
            validateTSNotTooEarly(timestamp, logs)

            const log = {...data, signature}
            addLogLine(creditPath, log)
            finish(201, '')
          }
          else if (type == 'CreateKey') {
            const index = parseInt(data.index)
            const nextIndex = getNextIndex(addressPath)
            if (!(index <= nextIndex)) throw new Error(`400:Index unknown or not next`)
            if (nextIndex === null) {
              const result = prv('generate', {chainId, address})
              if (result != 'created') throw new Error(`500:Unexpected generate result`)
              mkdirSync(addressPath, {recursive: true})
            }
            const {signing: path} = pathsFromIndex(index)
            const pubkey = prv('pubkey', {chainId, address, path})
            const logPath = `${addressPath}/${pubkey}`
            const existing = !(nextIndex == null || nextIndex == index)
            if (!existing) {
              const timestamp = Math.floor(Date.now() / 1000).toString()
              addLogLine(logPath, {type, timestamp, ...data, signature})
            }
            const statusCode = existing ? 200 : 201
            finish(statusCode, JSON.stringify(pubkey))
          }
          else if (['SetEnabled', 'SetFeeRecipient', 'SetGraffiti'].includes(type)) {
            const logsToAdd = []
            for (const [i, dataPubkey] of data.pubkeys.entries()) {
              const index = indices[i]
              const logPath = `${addressPath}/${dataPubkey}`
              if (!existsSync(logPath)) throw new Error(`400:Unknown pubkey`)
              const {signing: path} = pathsFromIndex(index)
              const pubkey = prv('pubkey', {chainId, address, path})
              if (pubkey !== dataPubkey) throw new Error(`400:Wrong pubkey for index ${index}`)
              const logs = readJSONL(logPath)
              if (!logs.length) throw new Error(`400:Pubkey ${pubkey} has no logs`)
              const timestamp = validateTimestamp(data.timestamp)
              validateTSNotTooEarly(timestamp, logs)

              const log = {type, ...data, signature}
              const keyCap = type.slice(3)
              const key = `${keyCap.slice(0, 1).toLowerCase()}${keyCap.slice(1)}`
              const lastLogOfType = logs.toReversed().find(({type: logType}) => logType == type)
              if (lastLogOfType?.[key] === data[key]) throw new Error(`400:Setting unchanged for ${pubkey}`)
              logsToAdd.push({logPath, log})
            }
            for (const {logPath, log} of logsToAdd)
              addLogLine(logPath, log)
            finish(201, '')
          }
          else {
            const logPath = `${addressPath}/${data.pubkey}`
            if (!existsSync(logPath)) throw new Error(`400:Unknown pubkey`)
            const {signing: path} = pathsFromIndex(index)
            const pubkey = prv('pubkey', {chainId, address, path})
            if (pubkey !== data.pubkey) throw new Error('400:Wrong pubkey for index')
            if (type == 'GetDepositData') {
              const depositData = computeDepositData({...data, chainId, address, path})
              finish(200, JSON.stringify(depositData))
            }
            else if (type == 'GetPresignedExit') {
              const presignedExit = computePresignedExit({...data, chainId, address, path})
              const timestamp = Math.floor(Date.now() / 1000).toString()
              addLogLine(logPath, {type, timestamp, ...data, signature})
              finish(200, JSON.stringify(presignedExit))
            }
            else throw new Error('400:Unknown instruction')
          }
          if (typesToRefresh.has(type)) {
            refreshActor().then(() => {
              console.debug("Actor refresh success.")
            })
          }
        }
        catch (e) { handler(e) }
      })
    }
    else
      throw new Error('405')
  }
  catch (e) { handler(e) }
}).listen(port)
