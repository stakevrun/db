import { gitCheck, gitPush, workDir, chainIds, addressRe, addressRegExp } from './lib.js'
import { spawnSync } from 'node:child_process'
import { mkdirSync, existsSync, readdirSync, writeFileSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
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
  const env = { COMMAND: cmd, CHAINID: chainId, ADDRESS: address }
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
  ], { env, input })
  if (res.status === 0)
    return res.stdout.toString().trimEnd()
  else if (res.stdout.toString().startsWith(errorPrefix))
    throw new Error(`500:${res.stdout.slice(errorPrefix.length)}`)
  else
    throw new Error(`500:prv failed: status ${res.status}, stdout '${res.stdout}', stderr '${res.stderr}'`)
}

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
// { type: string, data: <object>, signature: string }
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
//   uint256 timestamp;
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
// For instruction as a JSON object, we use string for uint256 (suitable to
// pass to BigInt), and use string (0x-prefixed lowercase hexstring) for bytes
// and address.
//
// We check the chainId in the URL matches the EIP712Domain chainId.
//
// Successful responses will have status 200 or 201 and an empty body or an
// application/json body for the following requests:
//
// CreateKey: { index: number, pubkey: string }
// where pubkey is the 0x-prefixed hexstring encoding the created key's pubkey
// and index is the index for that pubkey.
//
// GetDepositData: { depositDataRoot: string, signature: string }
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
const bytes32RegExp = /0x[0-9a-fA-F]{32}/
const structTypeRegExp = /(?<name>\w+)\((?<args>(?:\w+ \w+(?:,\w+ \w+)*)?)\)/

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
  'uint256 timestamp,bytes pubkey,bytes32 withdrawalCredentials,uint256 amountGwei'
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
        const body = (+getNextIndex(addressPath)).toString()
        resHeaders['Content-Length'] = Buffer.byteLength(body)
        res.writeHead(200, resHeaders)
        req.method == 'HEAD' ? res.end() : res.end(body)
      }
      else if (match.groups.i1 == 'pubkey') {
        if (!existsSync(addressPath)) throw new Error('404:Unknown address')
        const index = parseInt(match.groups.index)
        if (!(0 <= index)) throw new Error('400:Invalid index')
        const {signing: path} = pathsFromIndex(index)
        const pubkey = prv('pubkey', {chainId, address, path})
        if (!existsSync(`${addressPath}/${pubkey}`)) throw new Error(`400:Unknown index`)
        const body = pubkey
        resHeaders['Content-Length'] = Buffer.byteLength(body)
        res.writeHead(200, resHeaders)
        req.method == 'HEAD' ? res.end() : res.end(body)
      }
      else {
        if (!existsSync(addressPath)) throw new Error('404:Unknown address')
        const pubkey = [2, 3].map(i => match.groups[`pubkey${i}`]).find(x => x)
        const logPath = `${addressPath}/${pubkey}`
        const logs = readFileSync(logPath, 'utf8').trimEnd().split('\n').map(JSON.parse)
        if (match.groups.i2 == 'length') {
          const body = logs.length.toString()
          resHeaders['Content-Length'] = Buffer.byteLength(body)
          res.writeHead(200, resHeaders)
          req.method == 'HEAD' ? res.end() : res.end(body)
        }
        else if (match.groups.i3 == 'logs') {
          const start = url.searchParams.get('start')
          const endInt = parseInt(url.searchParams.get('end'))
          const end = Number.isNaN(endInt) ? logs.length : endInt
          const body = JSON.stringify(logs.slice(start, end))
          resHeaders['Content-Length'] = Buffer.byteLength(body)
          res.writeHead(200, resHeaders)
          req.method == 'HEAD' ? res.end() : res.end(body)
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
          if (!body) throw new Error('400:No data')
          const {type, data, signature} = JSON.parse(body)
          const typeMap = req.method == 'PUT' ? typesForPUT : typesForPOST
          if (!(typeMap.has(type))) throw new Error('400:Invalid type')
          let sig = signature.startsWith('0x') ? signature.slice(2, -2) : signature.slice(0, -2)
          const v = parseInt(`0x${signature.slice(-2)}`) - 27
          if (sig.length != 2 * 64) throw new Error(`400:Invalid signature length ${sig.length}`)
          try { sig = secp256k1.Signature.fromCompact(sig).addRecoveryBit(v) }
          catch (e) { throw new Error(`400:Invalid signature: ${e.message}`) }
          const domainSeparator = domainSeparators.get(chainId)
          const args = typeMap.get(type)
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
          const sigAddress = `0x${toHex(keccak256(pubkeyForKeccak).slice(-20))}`
          if (sigAddress !== address) throw new Error(`400:Address mismatch: ${sigAddress}`)
          const addressPath = `${workDir}/${chainId}/${address}`
          if (type == 'CreateKey') {
            const index = parseInt(data.index)
            const nextIndex = getNextIndex(addressPath)
            if (!(index <= nextIndex)) throw new Error(`400:Index unknown or not next`)
            if (nextIndex == null) {
              const result = prv('generate', {chainId, address})
              if (result != 'created') throw new Error(`500:Unexpected generate result`)
              mkdirSync(addressPath, {recursive: true})
            }
            const {signing: path} = pathsFromIndex(index)
            const pubkey = prv('pubkey', {chainId, address, path})
            const pubkeyPath = `${addressPath}/${pubkey}`
            const existing = !(nextIndex == null || nextIndex == index)
            if (!existing) {
              const timestamp = Math.floor(Date.now() / 1000).toString()
              const log = {type, timestamp, ...normaliseData(data, args.split(','))}
              writeFileSync(pubkeyPath, `${JSON.stringify(log)}\n`, {flag: 'a'})
              gitCheck(['add', pubkeyPath], workDir, '', `failed to log ${type}`)
              gitCheck(['diff', '--staged', '--numstat'], workDir,
                output => (
                  !output.trimEnd().includes('\n') &&
                  output.trimEnd().split(/\s+/).join() == `1,0,${chainId}/${address}/${pubkey}`
                ),
                `unexpected diff logging ${type}`
              )
              gitPush(type, workDir)
            }
            const statusCode = existing ? 200 : 201
            resHeaders['Content-Length'] = Buffer.byteLength(pubkey)
            res.writeHead(statusCode, resHeaders).end(pubkey)
          }
          else {
            throw new Error('501')
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
