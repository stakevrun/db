import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRe, addressRegExp, readJSONL } from './lib.js'
import { spawnSync } from 'node:child_process'
import { mkdirSync, existsSync, readdirSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { sha256 } from "ethereum-cryptography/sha256.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { hexToBytes, toHex, concatBytes } from "ethereum-cryptography/utils.js";

const port = 8880

// ERC-2334
const purpose = 12381
const coinType = 3600
const pathsFromIndex = index => {
  const prefix = `m/${purpose}/${coinType}/${index}`
  const withdrawal = `${prefix}/0`
  const signing = `${withdrawal}/0`
  return {withdrawal, signing}
}

const errorPrefix = 'error: '
const prv = (cmd, {chainId, address, path}, input) => {
  const env = {COMMAND: cmd, CHAINID: chainId, ADDRESS: address}
  if (path) env.KEYPATH = path
  const res = spawnSync('systemd-run', [
    '--quiet', '--collect', '--same-dir',
    '--wait', '--pipe',
    '--unit=vrunprv',
    '--expand-environment=no',
    '--property=DynamicUser=yes',
    '--property=StateDirectory=vrunprv', '--setenv=STATE_DIR=/var/lib/vrunprv',
    '--setenv=COMMAND', '--setenv=CHAINID', '--setenv=ADDRESS', '--setenv=KEYPATH',
    'node', 'prv'
  ], {env, input})
  if (res.status === 0)
    return res.stdout.toString().trimEnd()
  else if (res.stdout.toString().startsWith(errorPrefix))
    throw new Error(`500:${res.stdout.slice(errorPrefix.length)}`)
  else
    throw new Error(`500:prv failed: status ${res.status}, stdout '${res.stdout}', stderr '${res.stderr}'`)
}

ensureDirs()

// srv repository database layout:
// ${chainId}/${address}/${pubkey} : JSON lines of log entries
//
// the log is an append-only record of user instructions
//
// log entries are the 'instruction' objects described below with the pubkey
// field removed and a type key added.
//
// every change to the database is committed in work and pushed to bare
// if this succeeds we send back the successful HTTP response
// then we attempt to follow the instruction (except PUT requests are attempted
// before the response)

// srv: HTTP API
//
// all the GET requests return application/json content
//
// GET /<chainId>/<address>/nextindex
// returns: number - the next unused key index for address
//
// GET /<chainId>/<address>/pubkey/<index>
// returns: string - 0x-prefixed hexstring of the public key at the given index
// for the given address
//
// GET /<chainId>/<address>/<pubkey>/length
// returns: number - the number of log entries for this address and pubkey
//
// GET /<chainId>/<address>/<pubkey>/logs?start&end
// [<log>...] - log entries, with start and end interpreted as in
// returns: Array.prototype.slice, with the earliest logs first
//
// PUT (CreateKey) /<chainId>/<address>
// POST (the rest) /<chainId>/<address>/<index>
// the body content-type should be application/json
// the body should be JSON in the following format
//
// {type: string, data: <object>, signature: string}
//
// where signature is an EIP-712 signature over type{...data}
// encoded as a compact 0x-prefixed hexstring
//
// with EIP712Domain = {name: "vrün", version: "1", chainId: <chainId>}
//
// the possible instruction types are as follows:
//
// struct CreateKey {
//   uint256 index;
// }
//
// struct GetDepositData {
//   bytes pubkey;
//   bytes32 withdrawalCredentials;
//   uint256 amountGwei;
// }
//
// struct SetFeeRecipient {
//   uint256 timestamp;
//   bytes pubkey;
//   address feeRecipient;
// }
//
// struct SetGraffiti {
//   uint256 timestamp;
//   bytes pubkey;
//   string graffiti;
// }
//
// struct SetEnabled {
//   uint256 timestamp;
//   bytes pubkey;
//   bool enabled;
// }
//
// struct Exit {
//   uint256 timestamp;
//   bytes pubkey;
// }
//
// struct AddValidators {
//   uint256 timestamp;
//   uint256 firstIndex;
//   uint256 amountGwei;
//   address feeRecipient;
//   string graffiti;
//   address[] withdrawalAddresses;
// }
//
// For instruction as a JSON object, we use string for uint256 (suitable to
// pass to BigInt), and use string (0x-prefixed lowercase hexstring) for bytes
// and address.
//
// We check the chainId in the URL matches the EIP712Domain chainId.
//
// Successful responses will have status 200 or 201 and an empty body or an
// application/json body for the following requests:
//
// CreateKey: {index: number, pubkey: string}
// where pubkey is the 0x-prefixed hexstring encoding the created key's pubkey
// and index is the index for that pubkey.
//
// GetDepositData: {depositDataRoot: string, signature: string}
// where depositDataRoot is a 0x-prefixed hexstring of 32 bytes, and
// signature is a 0x-prefixed hexstring encoding a signature over
// depositDataRoot.
//
// Unsucessful responses will have status 400 or 500 depending on the problem:
//
// Any issues with processing the body (wrong content-type, bad signature,
// malformed instruction, invalid instruction): 400, plus a plain text error
// message body
//
// Any errors raised in processing the request will be relayed back in a plain
// text body with a 500 response.

const pubkeyRe = i => `(?<pubkey${i}>0x[0-9a-f]{96})`
const routesRegExp = new RegExp(`^/` +
  `(?<chainId>[0-9]+)/` +
  `(?<address>${addressRe})/(?:` +
    `(?<i0>nextindex)|` +
    `(?<i1>pubkey)/(?<index>[0-9]+)|` +
    `${pubkeyRe(2)}/(?<i2>length)|` +
    `${pubkeyRe(3)}/(?<i3>logs)|` +
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

const encodeData = (data, encodedType) => {
  if (encodedType == 'string') {
    if (typeof data != 'string') throw new Error('not a string')
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
      default:
        normalised[key] = data[key]
    }
  }
  return normalised
}

const typesForPUT = new Map()
const typesForPOST = new Map()

typesForPUT.set('CreateKey', 'uint256 index')

typesForPOST.set('GetDepositData',
  'bytes pubkey,bytes32 withdrawalCredentials,uint256 amountGwei'
)
typesForPOST.set('SetFeeRecipient',
  'uint256 timestamp,bytes pubkey,address feeRecipient'
)
typesForPOST.set('SetGraffiti',
  'uint256 timestamp,bytes pubkey,string graffiti'
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
  'address[] withdrawalAddresses'
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
  return {type, data: normaliseData(data, args.split(',')), address}
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

const computeDepositData = ({amountGwei, pubkey, withdrawalCredentials, chainId, address, path}) => {
  const amountBytes = new DataView(new ArrayBuffer(8))
  amountBytes.setBigUint64(0, BigInt(amountGwei), true)
  const pubkeyBytes = hexToBytes(pubkey)
  const pubkeyBytesPadded = new Uint8Array(64)
  pubkeyBytesPadded.set(pubkeyBytes)
  const wcAmountPadded = new Uint8Array(64)
  wcAmountPadded.set(hexToBytes(withdrawalCredentials))
  wcAmountPadded.set(new Uint8Array(amountBytes.buffer), 32)
  const depositMessageRootPrehash = new Uint8Array(64)
  depositMessageRootPrehash.set(sha256(pubkeyBytesPadded))
  depositMessageRootPrehash.set(sha256(wcAmountPadded), 32)
  const depositMessageRoot = sha256(depositMessageRootPrehash)
  const depositDomainType = Uint8Array.from([3, 0, 0, 0])
  const depositDataRootPrehash = new Uint8Array(64)
  const forkDataRoot = sha256(depositDataRootPrehash)
  const domain = concatBytes(depositDomainType, forkDataRoot.slice(0, 28))
  const signingRoot = sha256(depositMessageRoot, domain)
  const signature = prv('sign', {chainId, address, path}, signingRoot)
  const signatureBytes = hexToBytes(signature)
  const signature2 = new Uint8Array(64)
  signature2.set(signatureBytes.slice(64))
  depositDataRootPrehash.set(depositMessageRoot)
  depositDataRootPrehash.set(
    sha256(concatBytes(sha256(signatureBytes.slice(0, 64)), sha256(signature2))),
    32
  )
  const depositDataRoot = toHex(sha256(depositDataRootPrehash))
  return {depositDataRoot, signature}
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
        const logs = readJSONL(logPath)
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
          const {type, data, address: sigAddress} = verifyEIP712({domainSeparator, body, typeMap})
          if (sigAddress !== address) throw new Error(`400:Address mismatch: ${sigAddress}`)
          const addressPath = `${workDir}/${chainId}/${address}`
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
              const logs = existing && readJSONL(logPath)
              if (logs && !(parseInt(logs.at(-1).timestamp) <= timestamp)) throw new Error(`400:Timestamp too early`)
              if (logs?.some(({type}) => type == 'Exit')) throw new Error(`400:Already exited`)
              for (const [type, value] of [['SetFeeRecipient', data.feeRecipient],
                                           ['SetGraffiti', data.graffiti],
                                           ['SetEnabled', true]]) {
                const key = type.slice(3).toLowerCase()
                const lastLog = logs?.toReversed().find(({type: logType}) => logType == type)
                if (lastLog?.[key] === value) throw new Error(`400:Setting unchanged`)
                newLogsForPubkey.push({type, timestamp: timestamp.toString(), [key]: value})
              }
            }
            for (const [logPath, logs] of Object.entries(newLogsForPubkey)) {
              writeFileSync(logPath, logs.map(log => `${JSON.stringify(log)}\n`).join(''), {flag: 'a'})
              gitCheck(['add', logPath], workDir, '', `failed to add logs`)
            }
            const lineRegExp = new RegExp(`[34],0,${chainId}/${address}/${pubkeyRe('')}`)
            gitCheck(['diff', '--staged', '--numstat'], workDir,
              output => {
                const lines = output.trimEnd().split('\n')
                if (lines.length != withdrawalAddresses.length) return false
                const pubkeys = lines.map(line => lineRegExp.exec(line)?.groups.pubkey)
                return (Object.keys(depositDataByPubkey).every(x => pubkeys.includes(x)) &&
                        pubkeys.every(x => x in depositDataByPubkey))
              },
              `unexpected diff adding logs`
            )
            gitPush(type, workDir)
            finish(201, JSON.stringify(depositDataByPubkey))
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
              addLogLine(logPath, {type, timestamp, ...data})
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
            else {
              const logs = readJSONL(logPath)
              if (!logs.length) throw new Error(`400:Pubkey has no logs`)
              const lastLog = logs.at(-1)
              if (!(parseInt(lastLog.timestamp) <= parseInt(data.timestamp))) throw new Error(`400:Timestamp too early`)
              if (!(parseint(data.timestamp) <= (Date.now() / 1000))) throw new Error(`400:Timestamp in the future`)
              if (logs.some(({type}) => type == 'Exit')) throw new Error(`400:Already exited`)
              if (['SetEnabled', 'SetFeeRecipient', 'SetGraffiti'].includes(type)) {
                const key = type.slice(3).toLowerCase()
                const lastLog = logs.toReversed().find(({type: logType}) => logType == type)
                if (lastLog?.[key] === data[key])
                  throw new Error(`400:Setting unchanged`)
              }
              else if (type != 'Exit')
                throw new Error('400:Unknown instruction')
              const log = {type, ...data}
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
