import { createHash, createCipheriv, hkdfSync, scryptSync, randomUUID, randomBytes } from 'node:crypto'
import { mkdirSync, existsSync, realpathSync, readdirSync, writeFileSync, readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { hexToBytes, toHex, concatBytes } from "ethereum-cryptography/utils.js";

const chainIds = {1: 'mainnet', 17000: 'holesky'}

// ERC-2333

const sha256 = (m) => createHash('sha256').update(m).digest()
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n

function OS2IP(a) {
  let result = 0n
  let m = 1n
  for (const x of a.toReversed()) {
    result += BigInt(x) * m
    m *= 256n
  }
  return result
}

function I2OSP(n, l) {
  const result = new Uint8Array(l)
  while (l) {
    result[--l] = parseInt(n % 256n)
    n /= 256n
  }
  return result
}

const L = 48
const L2 = Uint8Array.from([0, L])
function secretKeyFromSeed(seed) {
  const seed0 = new Uint8Array(seed.length + 1)
  seed0.set(seed)
  let salt = 'BLS-SIG-KEYGEN-SALT-'
  let SK = 0n
  while (SK == 0n) {
    salt = sha256(salt)
    const OKM = new Uint8Array(hkdfSync('sha256', seed0, salt, L2, L))
    SK = OS2IP(OKM) % r
  }
  return SK
}

function lamportFromParent(sk, index) {
  const salt = I2OSP(BigInt(index), 4)
  const IKM = I2OSP(sk, 32)
  const lamport = []
  lamport.push(hkdfSync('sha256', IKM, salt, '', 32 * 255))
  const not_IKM = IKM.map(b => ~b)
  lamport.push(hkdfSync('sha256', not_IKM, salt, '', 32 * 255))
  const lamport_PK = new Uint8Array(2 * 32 * 255)
  for (const j of [0, 1]) {
    for (const i of Array(255).keys()) {
      const lamport_ji = new Uint8Array(lamport[j], i * 32, 32)
      lamport_PK.set(sha256(lamport_ji), (j * 255 + i) * 32)
    }
  }
  return sha256(lamport_PK)
}

const deriveChild = (sk, index) =>
  secretKeyFromSeed(lamportFromParent(sk, index))

// ERC-2334

const purpose = 12381
const coinType = 3600

const getPrefixKey = seed => {
  const m = secretKeyFromSeed(seed)
  const c1 = deriveChild(m, purpose)
  return deriveChild(c1, coinType)
}

const pathsFromIndex = index => {
  const prefix = `m/${purpose}/${coinType}/${index}`
  const withdrawal = `${prefix}/0`
  const signing = `${withdrawal}/0`
  return {withdrawal, signing}
}

const getValidatorKeys = ({seed, prefixKey}, index) => {
  prefixKey ??= getPrefixKey(seed)
  const indexKey = deriveChild(prefixKey, index)
  const withdrawal = deriveChild(indexKey, 0)
  const signing = deriveChild(withdrawal, 0)
  return {withdrawal, signing}
}

// Get pubkey from privkey sk
// pubkey = sk * g1 (or just its x coordinate for compressed (48 byte) form)
// where g1 is the conventional G1 generator of BLS12-381, see
// https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#generators or
// https://github.com/paulmillr/noble-curves/blob/2f1460a4d7f31e5a61db9606266f5b9a5c659c9d/src/bls12-381.ts#L1100
//
// To do this multiplication, we use the naive double and add algorithm
// For doubling and adding, we use Algorithms 8 and 9 in https://eprint.iacr.org/2015/1060.pdf

const g1 = {
  x: 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507n,
  y: 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569n
}

const order = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n
const b3 = 3n * 4n

const mod = (a, b) => {
  const r = a % b
  return r < 0n ? b + r : r
}
const addm = (x, y) => mod(x + y, order)
const subm = (x, y) => mod(x - y, order)
const mulm = (x, y) => mod(x * y, order)

// Algorithm 8
const addp = ({x: x1, y: y1, z: z1}, {x: x2, y: y2}) => {
  let t0, t1, t2, t3, t4, x3, y3, z3
  t0 = mulm(x1, x2) //  1
  t1 = mulm(y1, y2) //  2
  t3 = addm(x2, y2) //  3
  t4 = addm(x1, y1) //  4
  t3 = mulm(t3, t4) //  5
  t4 = addm(t0, t1) //  6
  t3 = subm(t3, t4) //  7
  t4 = mulm(y2, z1) //  8
  t4 = addm(t4, y1) //  9
  y3 = mulm(x2, z1) // 10
  y3 = addm(y3, x1) // 11
  x3 = addm(t0, t0) // 12
  t0 = addm(x3, t0) // 13
  t2 = mulm(b3, z1) // 14
  z3 = addm(t1, t2) // 15
  t1 = subm(t1, t2) // 16
  y3 = mulm(b3, y3) // 17
  x3 = mulm(t4, y3) // 18
  t2 = mulm(t3, t1) // 19
  x3 = subm(t2, x3) // 20
  y3 = mulm(y3, t0) // 21
  t1 = mulm(t1, z3) // 22
  y3 = addm(t1, y3) // 23
  t0 = mulm(t0, t3) // 24
  z3 = mulm(z3, t4) // 25
  z3 = addm(z3, t0) // 26
  return {x: x3, y: y3, z: z3}
}

// Algorithm 9
const dblp = ({x, y, z}) => {
  let t0, t1, t2, x3, y3, z3
  t0 = mulm(y, y)    //  1
  z3 = addm(t0, t0)  //  2
  z3 = addm(z3, z3)  //  3
  z3 = addm(z3, z3)  //  4
  t1 = mulm(y, z)    //  5
  t2 = mulm(z, z)    //  6
  t2 = mulm(b3, t2)  //  7
  x3 = mulm(t2, z3)  //  8
  y3 = addm(t0, t2)  //  9
  z3 = mulm(t1, z3)  // 10
  t1 = addm(t2, t2)  // 11
  t2 = addm(t1, t2)  // 12
  t0 = subm(t0, t2)  // 13
  y3 = mulm(t0, y3)  // 14
  y3 = addm(x3, y3)  // 15
  t1 = mulm(x, y)    // 16
  x3 = mulm(t0, t1)  // 17
  x3 = addm(x3, x3)  // 18
  return {x: x3, y: y3, z: z3}
}

const mulp = (n, p) => {
  const {x, y} = p
  const bits = []
  while (n) {
    bits.push(n % 2n)
    n >>= 1n
  }
  let res = {x, y, z: 1n}
  bits.pop()
  while (bits.length) {
    res = dblp(res)
    if (bits.pop())
      res = addp(res, p)
  }
  return res
}

// modular multiplicative inverse using extended Euclidean algorithm
const invert = z => {
  let t = 0n, u = 1n, r = order
  while (z) {
    const q = r / z
    const m = t - q * u
    const n = r - q * z
    t = u, u = m, r = z, z = n
  }
  return t < 0n ? t + order : t
}

const toAffine = ({x, y, z}) => {
  const zi = invert(z)
  return {x: mulm(x, zi), y: mulm(y, zi)}
}

// Three flag bits are added to the raw x coordinate, as described here
// https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
const pubkeyFromPrivkey = (sk) => {
  const {x, y} = toAffine(mulp(sk, g1))
  const bytes = I2OSP(x, 48)
  bytes[0] |= ((y * 2n) / order) ? 0b10100000 : 0b10000000
  return bytes
}

// ERC-2335

const password = 'Never Gonna Give You Up'

const generateKeystore = ({sk, path, pubkey}) => {
  pubkey ??= pubkeyFromPrivkey(sk)
  if (typeof pubkey != 'string') pubkey = toHex(pubkey)
  else if (pubkey.startsWith('0x')) pubkey = pubkey.slice(2)

  const saltBytes = randomBytes(32)
  const salt = toHex(saltBytes)

  const dklen = 32
  const r = 8
  const p = 1
  const n = 16384
  const derivedKey = scryptSync(password, saltBytes, dklen, {r, p, N: n})
  const algorithm = 'aes-128-ctr'
  const ivBytes = randomBytes(16)
  const iv = toHex(ivBytes)

  const dk = derivedKey.slice(0, 16)
  const ck = derivedKey.slice(16)

  const cipher = createCipheriv(algorithm, dk, ivBytes)
  const data = I2OSP(sk, 32)
  cipher.setAutoPadding(false)
  const enc1 = cipher.update(data, null, 'hex')
  const enc2 = cipher.final('hex')
  const cipherMessage = `${enc1}${enc2}`

  const hash = createHash('sha256')
  hash.update(ck)
  hash.update(cipherMessage, 'hex')
  const checksumMessage = hash.digest('hex')

  const keystore = {
    crypto: {
      kdf: { function: 'scrypt', params: { dklen, n, p, r, salt }, message: '' },
      checksum: { function: 'sha256', params: {}, message: checksumMessage },
      cipher: { function: algorithm, params: { iv }, message: cipherMessage },
    },
    path,
    pubkey,
    uuid: randomUUID(),
    version: 4
  }

  return keystore
}

// addresses are lowercase hexstrings with the 0x prefix
// pubkeys are lowercase hexstrings with the 0x prefix
// timestamps are integers representing seconds since UNIX epoch
// contents are utf8 encoded unless otherwise specified
//
// we use a git repository for the database
// the main copy is an append-only bare repository bare
// the working copy for editing and committing is work
//
// repository database layout:
// ${chainId}/${address}/init : timestamp
// ${chainId}/${address}/seed : 32 bytes (no encoding)
// ${chainId}/${address}/${pubkey}/log : JSON lines of log entries
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
//
// HTTP API
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
// PUT (CreateKey) or POST (the rest) /<chainId>/<address>
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
//   uint256 amountGwei;
//   bytes32 withdrawalCredentials;
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

// Expected setup can be created as follows:
// git init --bare <bareDir>
// cd <bareDir>
// git config receive.denyNonFastForwards true
// git config receive.denyDeletes true
// cd -
// git clone --no-hardlinks <bareDir> <workDir>
// cd <workDir>
// git commit --allow-empty -m 'init'
// git push
// cd -
// ln -s <bareDir> ./bare
// ln -s <workDir> ./work

if (!existsSync('bare'))
  throw new Error(`bare directory missing`)

const gitCheck = (args, cwd, expectedOutput, msg) => {
  const res = spawnSync('git', args, {cwd})
  const checkOutput = typeof expectedOutput == 'string' ? (s => s === expectedOutput) : expectedOutput
  if (!(res.status === 0 && checkOutput(String(res.stdout))))
    throw new Error(msg + ` ${res.status} '${res.stdout}' '${res.stderr}'`)
}

gitCheck(['rev-parse', '--is-bare-repository'], 'bare', 'true\n', 'bare is not a bare git repository')

gitCheck(['config', 'receive.denyNonFastForwards'], 'bare', 'true\n', 'bare does not deny non-fast-forwards')
gitCheck(['config', 'receive.denyDeletes'], 'bare', 'true\n', 'bare does not deny deletes')

const bareRealPath = realpathSync('bare')

if (!existsSync('work'))
  throw new Error(`work directory missing`)

gitCheck(['status', '--porcelain'], 'work', '', 'work directory not clean')

gitCheck(['rev-parse', '--abbrev-ref', '@{upstream}'], 'work', 'origin/main\n', 'work upstream not origin/main')

gitCheck(['config', 'remote.origin.url'], 'work',
  s => realpathSync(s.trim()) === bareRealPath,
  'work remote is not bare')

const addressRe = '0x[0-9a-f]{40}'
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
const addressRegExp = new RegExp(addressRe)

const numberRegExp = /[1-9][0-9]*/
const hexStringRegExp = /0x[0-9a-f]*/
const bytes32RegExp = /0x[0-9a-f]{32}/
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
    if (typeof data == 'string' &&
        !(hexStringRegExp.test(data) ||
          encodedType == 'uint256' && numberRegExp.test(data)))
      throw new Error('not a hexstring')
    return I2OSP(BigInt(data), 32)
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

const typesForPUT = new Map()
typesForPUT.set('CreateKey', '(uint256 index)')

const typesForPOST = new Map()
typesForPOST.set('GetDepositData',
  '(uint256 timestamp,bytes pubkey,uint256 amountGwei,bytes32 withdrawalCredentials)'
)
typesForPOST.set('SetFeeRecipient',
  '(uint256 timestamp,bytes pubkey,address feeRecipient)'
)
typesForPOST.set('SetGraffiti',
  '(uint256 timestamp,bytes pubkey,string graffiti)'
)
typesForPOST.set('SetEnabled',
  '(uint256 timestamp,bytes pubkey,bool enabled)'
)
typesForPOST.set('Exit',
  '(uint256 timestamp,bytes pubkey)'
)

const getNextIndex = addressPath => {
  if (!existsSync(`${addressPath}/init`))
    return null
  else {
    const dir = readdirSync(addressPath)
    if (!(2 <= dir.length)) throw new Error('500:Unexpectedly few entries')
    return dir.length - 2
  }
}

const getTimestamp = () => Math.floor(Date.now() / 1000)

createServer((req, res) => {
  function handler(e) {
    let [code, body] = e.message.split(':', 2)
    if (body) body += e.message.slice(code.length + 1 + body.length)
    const statusCode = parseInt(code) || 500
    if (!body && statusCode == 500) body = e.message
    if (body) {
      if (statusCode == 405) {
        const headers = {'Allow': body}
        res.writeHead(statusCode, headers).end()
      }
      else {
        const headers = {
          'Content-Type': 'text/plain',
          'Content-Length': Buffer.byteLength(body)
        }
        res.writeHead(statusCode, headers).end(body)
      }
    }
    else {
      res.writeHead(statusCode).end()
    }
  }
  try {
    const resHeaders = {'Content-Type': 'application/json'}
    const url = new URL(req.url, `http://${req.headers.host}`)
    const pathname = url.pathname.toLowerCase()
    if (req.method == 'GET') {
      const match = routesRegExp.exec(pathname)
      if (!match) throw new Error('404:Unknown route')
      const chainId = parseInt(match.groups.chainId)
      const chain = chainIds[chainId]
      if (!chain) throw new Error('404:Unknown chainId')
      const address = match.groups.address
      const addressPath = `work/${chainId}/${address}`
      if (match.groups.i0 = 'nextindex') {
        const body = (+getNextIndex(addressPath)).toString()
        resHeaders['Content-Length'] = Buffer.byteLength(body)
        res.writeHead(200, resHeaders).end(body)
      }
      else if (match.groups.i1 == 'pubkey') {
        if (!existsSync(`${addressPath}/init`)) throw new Error('404:Unknown address')
        const index = parseInt(match.groups.index)
        if (!(0 <= index)) throw new Error('400:Invalid index')
        const seed = new Uint8Array(readFileSync(`${addressPath}/seed`))
        const {signing: path} = pathsFromIndex(index)
        const {signing: sk} = getValidatorKeys({seed}, index)
        const pubkey = `0x${toHex(pubkeyFromPrivkey(sk))}`
        if (!existsSync(`${addressPath}/${pubkey}/log`)) throw new Error(`400:Unknown index`)
        resHeaders['Content-Length'] = Buffer.byteLength(pubkey)
        res.writeHead(200, resHeaders).end(pubkey)
      }
      else {
        if (!existsSync(`${addressPath}/init`)) throw new Error('404:Unknown address')
        const pubkey = [2, 3].map(i => match.groups[`pubkey${i}`]).find(x => x)
        const logPath = `${addressPath}/${pubkey}/log`
        const logs = JSON.parse(readFileSync(logPath))
        if (match.groups.i2 == 'length') {
          const body = logs.length.toString()
          resHeaders['Content-Length'] = Buffer.byteLength(body)
          res.writeHead(200, resHeaders).end(body)
        }
        else if (match.groups.i3 == 'logs') {
          const start = url.searchParams.get('start')
          const endInt = parseInt(url.searchParams.get('end'))
          const end = Number.isNaN(endInt) ? logs.length : endInt
          const body = JSON.stringify(logs.slice(start, end))
          resHeaders['Content-Length'] = Buffer.byteLength(body)
          res.writeHead(200, resHeaders).end(body)
        }
        else {
          throw new Error('404:Unexpected route')
        }
      }
    }
    else {
      const [, chainId, address] = pathname.split('/')
      if (!domainSeparators.has(chainId)) throw new Error('404:Unknown chainId')
      if (!addressRegExp.test(address)) throw new Error('404:Invalid address')
      const [contentType, charset] = req.headers['content-type']?.split(';') || []
      if (contentType !== 'application/json')
        throw new Error('415:Accepts application/json only')
      if (charset && charset.trim().toLowerCase() !== 'charset=utf-8')
        throw new Error('415:Accepts charset=utf-8 only')
      if (!['PUT', 'POST'].includes(req.method)) throw new Error('405:PUT,POST')
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
          let message
          try {
            message = concatBytes(
              Buffer.from('\x19\x01'), domainSeparator,
              hashStruct(data, `${type}${typeMap.get(type)}`)
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
          const addressPath = `${chainId}/${address}`
          const workAddressPath = `work/${addressPath}`
          if (type == 'CreateKey') {
            const index = parseInt(data.index)
            const nextIndex = getNextIndex(workAddressPath)
            if (!(index <= nextIndex)) throw new Error(`400:Index unknown or not next`)
            let seed
            if (nextIndex == null) {
              seed = randomBytes(32)
              mkdirSync(workAddressPath, {recursive: true})
              writeFileSync(`${workAddressPath}/init`, getTimestamp().toString(), {flag: 'wx'})
              writeFileSync(`${workAddressPath}/seed`, seed, {flag: 'wx'})
              gitCheck(['add', addressPath], 'work', '', 'could not add seed')
              gitCheck(['diff', '--staged', '--numstat'], 'work',
                output => {
                  const lines = output.split('\n')
                  return (
                    lines.length == 2 &&
                    lines[0].split(/\s+/).join() == `1,0,${addressPath}/init` &&
                    lines[1].split(/\s+/).join() == `-,-,${addressPath}/seed`
                  )
                },
                'unexpected diff after adding seed'
              )
              gitCheck(['commit', '--message', `init ${address}`], 'work', '', 'could not commit seed')
              gitCheck(['push', '--porcelain'], 'work',
                output => {
                  const lines = output.split('\n')
                  return (
                    lines.length == 1 &&
                    lines[0].startsWith('*')
                  )
                },
                'failed to push seed commit'
              )
            }
            const prefixKey = getPrefixKey(seed)
            const {signing: sk} = getValidatorKeys({prefixKey}, index)
            const pubkey = `0x${toHex(pubkeyFromPrivkey(sk))}`
            const workKeyPath = `${workAddressPath}/${pubkey}`
            const existing = !(nextIndex == null || nextIndex == index)
            if (nextIndex == null)
              mkdirSync(workKeyPath, {recursive: true})
            if (!existing) {
              const log = {type, ...data}
              writeFileSync(`${workKeyPath}/log`, `${JSON.stringify(log)}\n`, {flag: 'a'})
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
  }
  catch (e) { handler(e) }
}).listen(8880)

// TODO: calculate EIP-712 type hashes for all the messages we might get

// old code below

/*
if (process.env.COMMAND == 'test') {
  const testCases = [
    {
      seed: '0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
      master_SK: 6083874454709270928345386274498605044986640685124978867557563392430687146096n,
      child_index: 0,
      child_SK: 20397789859736650942317412262472558107875392172444076792671091975210932703118n
    },
    {
      seed: '0x3141592653589793238462643383279502884197169399375105820974944592',
      master_SK: 29757020647961307431480504535336562678282505419141012933316116377660817309383n,
      child_index: 3141592653,
      child_SK: 25457201688850691947727629385191704516744796114925897962676248250929345014287n
    },
    {
      seed: '0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00',
      master_SK: 27580842291869792442942448775674722299803720648445448686099262467207037398656n,
      child_index: 4294967295,
      child_SK: 29358610794459428860402234341874281240803786294062035874021252734817515685787n
    },
    {
      seed: '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',
      master_SK: 19022158461524446591288038168518313374041767046816487870552872741050760015818n,
      child_index: 42,
      child_SK: 31372231650479070279774297061823572166496564838472787488249775572789064611981n
    }
  ]
  for (const [i, {seed, master_SK, child_index, child_SK}] of testCases.entries()) {
    const seedBytes = hexToBytes(seed)
    const sk = secretKeyFromSeed(seedBytes)
    const csk = deriveChild(sk, child_index)
    if (sk == master_SK) {
      if (csk == child_SK)
        console.log(`Test case ${i} passed`)
      else {
        throw new Error(`Test case ${i} failed: Got ${csk} instead of ${child_SK}`)
      }
    }
    else {
      throw new Error(`Test case ${i} failed: Got ${sk} instead of ${master_SK}`)
    }
  }
  const privkey = OS2IP([
    21, 174, 215, 242, 174,  16,  11,  65,
    60,  73,  41,  24, 106, 150,  80, 174,
    41, 246, 248,  76,  46, 174, 109,  75,
    77,  89,   1, 100, 227,  20,  60, 201
  ])
  const expectedPubkey = '0x8a0f14c0efe188fbace5b4a72f9e24ce6484b83d2a266837f69f748dafccfdcb12167f5427b7801367a32bf63fdf4783'
  const pubkey = pubkeyFromPrivkey(privkey)
  const hexPubkey = `0x${toHex(pubkey)}`
  if (hexPubkey == expectedPubkey)
    console.log(`Test pubkey passed`)
  else {
    throw new Error(`Test pubkey failed: Got ${pubkey} i.e. ${hexPubkey} instead of ${expectedPubkey}`)
  }
  process.exit()
}

if (process.env.COMMAND == 'init') {
  const dirPath = `db/${chainId}/${address}`
  mkdirSync(dirPath, {recursive: true})
  writeFileSync(`${dirPath}/init`, getTimestamp().toString(), {flag: 'wx'})
  writeFileSync(`${dirPath}/seed`, randomBytes(32), {flag: 'wx'})
  process.exit()
}

else if (process.env.COMMAND == 'create') {
  const dirPath = `db/${chainId}/${address}`
  const seed = new Uint8Array(readFileSync(`${dirPath}/seed`))
  const prefixKey = getPrefixKey(seed)
  const startIndex = parseInt(process.env.INDEX) || 0
  let index = startIndex, sk, pubkey, keyPath
  while (true) {
    ({signing: sk} = getValidatorKeys({prefixKey}, index))
    pubkey = `0x${toHex(pubkeyFromPrivkey(sk))}`
    keyPath = `${dirPath}/${pubkey}`
    if (existsSync(`${keyPath}/log`)) index++
    else break
  }
  const log = {type: 'create', time: getTimestamp(), data: index}
  mkdirSync(keyPath, {recursive: true})
  writeFileSync(`${keyPath}/log`, `${JSON.stringify(log)}\n`, {flag: 'wx'})
  console.log(`Added pubkey ${pubkey} at index ${index} for ${address} on ${chain}`)
  process.exit()
}

else if (process.env.COMMAND == 'keystore') {
  const dirPath = `db/${chainId}/${address}`
  const seed = new Uint8Array(readFileSync(`${dirPath}/seed`))

  const indexFromLog = async (pubkey) => {
    const logPath = `${dirPath}/${pubkey}/log`
    const logStream = createReadStream(logPath)
    const lineReader = createInterface({input: logStream})
    let index
    lineReader.once('line', (line) => {
      const {type, data} = JSON.parse(line)
      if (type != 'create')
        throw new Error(`No create in first line of log ${line}`)
      index = data
      lineReader.close()
    })
    await once(lineReader, 'close')
    if (0 <= index) return index
    else throw new Error(`Failed to get index from ${logPath}`)
  }

  const index = parseInt(
    0 <= process.env.INDEX ?
    process.env.INDEX :
    await indexFromLog(process.env.PUBKEY)
  )
  const {signing: path} = pathsFromIndex(index)
  const {signing: sk} = getValidatorKeys({seed}, index)
  const pubkey = process.env.PUBKEY || pubkeyFromPrivkey(sk)

  if (!existsSync(`${dirPath}/${typeof pubkey == 'string' ? pubkey : `0x${toHex(pubkey)}`}/log`))
    throw new Error(`Key at ${index} not generated`)

  const ksp = generateKeystore({sk, pubkey, path})

  console.log(JSON.stringify(ksp))
  process.exit()
}

else {
  console.error(`Not implemented yet: ${process.env.COMMAND}`)
  process.exit(1)
}
*/
