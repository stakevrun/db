import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRe, addressRegExp, readJSONL, pathsFromIndex, genesisForkVersion, capellaForkVersion, prv } from './lib.js'
import { spawnSync } from 'node:child_process'
import { mkdirSync, existsSync, readdirSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { sha256 } from "ethereum-cryptography/sha256.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { hexToBytes, toHex, concatBytes } from "ethereum-cryptography/utils.js";

const port = 8880

ensureDirs()

// srv repository database layout:
// ${chainId}/a/${address} : JSON lines of signed acceptances of the terms of service
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

const pubkeyRe = i => `(?<pubkey${i}>0x[0-9a-f]{96})`
const routesRegExp = new RegExp(`^/` +
  `(?<chainId>[0-9]+)/` +
  `(?<address>${addressRe})/(?:` +
    `(?<i0>nextindex)|` +
    `(?<i1>pubkey)/(?<index>[0-9]+)|` +
    `${pubkeyRe(2)}/(?<i2>length)|` +
    `${pubkeyRe(3)}/(?<i3>logs)|` +
    `(?<i4>acceptance)` +
  `)$`
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

const requiredDeclaration = 'I accept the terms of service specified at https://vrün.com/terms (with version identifier 20240229).'

const typesForPUT = new Map()
const typesForPOST = new Map()

typesForPUT.set('AcceptTermsOfService', 'string declaration')
typesForPUT.set('CreateKey', 'uint256 index')

typesForPOST.set('GetDepositData',
  'bytes pubkey,bytes32 withdrawalCredentials,uint256 amountGwei'
)
typesForPOST.set('GetPresignedExit',
  'bytes pubkey,uint256 validatorIndex,uint256 epoch'
)
typesForPOST.set('SetFeeRecipient',
  'uint256 timestamp,bytes pubkey,address feeRecipient'
)
typesForPOST.set('SetGraffiti',
  'uint256 timestamp,bytes pubkey,string graffiti'
)
typesForPOST.set('SetName',
  'uint256 timestamp,bytes pubkey,string name'
)
typesForPOST.set('SetEnabled',
  'uint256 timestamp,bytes pubkey,bool enabled'
)
typesForPOST.set('Exit',
  'uint256 timestamp,bytes pubkey'
)
typesForPOST.set('AddValidators',
  'uint256 timestamp,uint256 firstIndex,' +
  'uint256 amountGwei,address feeRecipient,string graffiti,' +
  'address[] withdrawalAddresses,string[] names'
)

const verifyEIP712 = ({body, domainSeparator, typeMap}) => {
  if (!body) throw new Error('400:No data')
  const {type, data, signature} = JSON.parse(body)
  if (!(typeMap.has(type))) throw new Error('400:Invalid type')
  const args = typeMap.get(type)
  let sig = signature.startsWith('0x') ? signature.slice(2, -2) : signature.slice(0, -2)
  const v = parseInt(`0x${signature.slice(-2)}`) - 27
  if (sig.length != 2 * 64) throw new Error(`400:Invalid signature length ${sig.length}`)
  try { sig = secp256k1.Signature.fromCompact(sig).addRecoveryBit(v) }
  catch (e) { throw new Error(`400:Invalid signature: ${e.message}`) }
  let message
  try {
    message = concatBytes(
      Buffer.from('\x19\x01'), domainSeparator,
      hashStruct(data, `${type}(${args})`)
    )
  }
  catch (e) { throw new Error(`400:Invalid data: ${e.message}`) }
  const msgHash = keccak256(message)
  const sigPubkey = sig.recoverPublicKey(msgHash)
  const verified = secp256k1.verify(sig, msgHash, sigPubkey.toRawBytes())
  if (!verified) throw new Error(`400:Invalid signature`)
  const pubkeyForKeccak = sigPubkey.toRawBytes(false).slice(1)
  if (pubkeyForKeccak.length != 64) throw new Error(`500:Unexpected pubkey length ${toHex(pubkeyForKeccak)}`)
  const address = `0x${toHex(keccak256(pubkeyForKeccak).slice(-20))}`
  return {type, data: normaliseData(data, args.split(',')), address, signature}
}

const addLogLine = (logPath, log) => {
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
  const signature = prv('sign', {chainId, address, path}, signingRoot)
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
  const signature = prv('sign', {chainId, address, path}, signingRoot)
  return {signature, message: {epoch, validator_index: validatorIndex}}
}

const allowedMethods = 'GET,HEAD,OPTIONS,POST,PUT'

createServer((req, res) => {
  const resHeaders = {
    'Access-Control-Allow-Origin': '*'
  }
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
        res.method == 'HEAD' ? res.end() : res.end(body)
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
    req.method == 'HEAD' ? res.end() : res.end(body)
    console.log(`${req.method} ${req.url} -> ${statusCode}: ${body}`)
  }
  try {
    resHeaders['Content-Type'] = 'application/json'
    const url = new URL(req.url, `http://${req.headers.host}`)
    const pathname = url.pathname.toLowerCase()
    if (['GET', 'HEAD'].includes(req.method)) {
      const match = routesRegExp.exec(pathname)
      if (!match) throw new Error('404:Unknown route')
      const chainId = parseInt(match.groups.chainId)
      const chain = chainIds[chainId]
      if (!chain) throw new Error('404:Unknown chainId')
      const address = match.groups.address
      const addressPath = `${workDir}/${chainId}/${address}`
      if (match.groups.i0 == 'nextindex') {
        finish(200, (+getNextIndex(addressPath)).toString())
      }
      else if (match.groups.i4 == 'acceptance') {
        const acceptancePath = `${workDir}/${chainId}/a/${address}`
        if (!existsSync(acceptancePath)) throw new Error(`404:Acceptance missing`)
        const {timestamp, declaration, signature} = readJSONL(acceptancePath).at(-1)
        finish(200, JSON.stringify({timestamp, declaration, signature}))
      }
      else if (match.groups.i1 == 'pubkey') {
        if (!existsSync(addressPath)) throw new Error('404:Unknown address')
        const index = parseInt(match.groups.index)
        if (!(0 <= index)) throw new Error('400:Invalid index')
        const {signing: path} = pathsFromIndex(index)
        const pubkey = prv('pubkey', {chainId, address, path})
        if (!existsSync(`${addressPath}/${pubkey}`)) throw new Error(`400:Unknown index`)
        finish(200, JSON.stringify(pubkey))
      }
      else {
        if (!existsSync(addressPath)) throw new Error('404:Unknown address')
        const pubkey = [2, 3].map(i => match.groups[`pubkey${i}`]).find(x => x)
        const logPath = `${addressPath}/${pubkey}`
        if (!existsSync(logPath)) throw new Error('404:Unknown pubkey')
        const unfiltered = readJSONL(logPath)
        const type = url.searchParams.get('type')
        const test = type && new RegExp(type, 'i')
        const logs = type ? unfiltered.flatMap(x => test.test(x.type) ? [x] : []) : unfiltered
        if (match.groups.i2 == 'length') {
          finish(200, logs.length.toString())
        }
        else if (match.groups.i3 == 'logs') {
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
      const [, chainId, address, index] = pathname.split('/')
      if (!domainSeparators.has(chainId)) throw new Error('404:Unknown chainId')
      if (!addressRegExp.test(address)) throw new Error('404:Invalid address')
      if (typeof index == 'string' && !numberRegExp.test(index)) throw new Error('404:Invalid index')
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
          const {type, data, address: sigAddress, signature} = verifyEIP712({domainSeparator, body, typeMap})
          if (sigAddress !== address) throw new Error(`400:Address mismatch: ${sigAddress}`)
          const addressPath = `${workDir}/${chainId}/${address}`
          const acceptanceDir = `${workDir}/${chainId}/a`
          const acceptancePath = `${acceptanceDir}/${address}`
          const acceptanceExists = existsSync(acceptancePath)
          const {declaration: currentDeclaration} = acceptanceExists && readJSONL(acceptancePath).at(-1)
          if (currentDeclaration !== requiredDeclaration && type != 'AcceptTermsOfService')
            throw new Error('400:Acceptance of terms of service missing')
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
            const timestamp = parseInt(data.timestamp)
            if (!(timestamp <= (Date.now() / 1000))) throw new Error(`400:Timestamp in the future`)
            if (data.withdrawalAddresses.length !== data.names.length)
              throw new Error(`400:Mismatching numbers of names and withdrawal addresses`)
            let index = firstIndex
            for (const [i, withdrawalAddress] of data.withdrawalAddresses.entries()) {
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
              if (logs.length && !(parseInt(logs.at(-1).timestamp) <= timestamp)) throw new Error(`400:Timestamp too early`)
              if (logs.some(({type}) => type == 'Exit')) throw new Error(`400:Already exited`)
              for (const [type, value] of [['SetFeeRecipient', data.feeRecipient],
                                           ['SetGraffiti', data.graffiti],
                                           ['SetName', data.names[i]],
                                           ['SetEnabled', true]]) {
                const key = type.slice(3).toLowerCase()
                const lastLog = logs.toReversed().find(({type: logType}) => logType == type)
                if (lastLog?.[key] === value) throw new Error(`400:Setting unchanged`)
                newLogsForPubkey.push({type, timestamp: timestamp.toString(), [key]: value})
              }
            }
            for (const [logPath, logs] of Object.entries(newLogs)) {
              writeFileSync(logPath, logs.map(log => `${JSON.stringify(log)}\n`).join(''), {flag: 'a'})
              gitCheck(['add', logPath], workDir, '', `failed to add logs`)
            }
            const lineRegExp = new RegExp(`[45]\\s+0\\s+${chainId}/${address}/${pubkeyRe('')}`)
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
            const existing = currentDeclaration === data.declaration
            if (!acceptanceExists) mkdirSync(acceptanceDir, {recursive: true})
            if (!existing) {
              const timestamp = Math.floor(Date.now() / 1000).toString()
              addLogLine(acceptancePath, {type, timestamp, ...data, signature})
            }
            const statusCode = existing ? 200 : 201
            finish(statusCode, '')
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
            else {
              const logs = readJSONL(logPath)
              if (!logs.length) throw new Error(`400:Pubkey has no logs`)
              const lastLog = logs.at(-1)
              if (!(parseInt(lastLog.timestamp) <= parseInt(data.timestamp))) throw new Error(`400:Timestamp too early`)
              if (!(parseInt(data.timestamp) <= (Date.now() / 1000))) throw new Error(`400:Timestamp in the future`)
              if (logs.some(({type}) => type == 'Exit')) throw new Error(`400:Already exited`)
              if (['SetEnabled', 'SetFeeRecipient', 'SetGraffiti', 'SetName'].includes(type)) {
                const key = type.slice(3).toLowerCase()
                const lastLog = logs.toReversed().find(({type: logType}) => logType == type)
                if (lastLog?.[key] === data[key])
                  throw new Error(`400:Setting unchanged`)
              }
              else if (type != 'Exit')
                throw new Error('400:Unknown instruction')
              const log = {type, ...data, signature}
              delete log.pubkey
              addLogLine(logPath, log)
              finish(201, '')
            }
          }
        }
        catch (e) { handler(e) }
      })
    }
    else if (req.method == 'OPTIONS') {
      resHeaders['Content-Length'] = 0
      resHeaders['Access-Control-Allow-Methods'] = allowedMethods
      resHeaders['Access-Control-Allow-Headers'] = '*'
      res.writeHead(204, resHeaders).end()
    }
    else
      throw new Error('405')
  }
  catch (e) { handler(e) }
}).listen(port)
