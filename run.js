import 'dotenv/config'
import { createHash, createCipheriv, hkdfSync, scryptSync, randomUUID, randomBytes } from 'node:crypto'
import { mkdirSync, existsSync, writeFileSync, readFileSync, createReadStream } from 'node:fs'
import { createInterface } from 'node:readline'
import { once } from 'node:events'
import { ethers } from 'ethers'

const chainIds = {1: 'mainnet', 17000: 'holesky'}
const chainId = process.env.CHAIN ?
  Object.entries(chainIds).find(([k, v]) => [k, v].some(x => x == process.env.CHAIN))?.[0] :
  1
const chain = chainIds[chainId]
console.log(`On chain ${chain}`)

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

const toHex = a => ethers.hexlify(a).slice(2)
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

// addresses are checksummed (ERC-55) hexstrings with the 0x prefix
// pubkeys are lowercase hexstrings with the 0x prefix
// timestamps are integers representing seconds since UNIX epoch
// contents are utf8 encoded unless otherwise specified
//
// filesystem database layout:
// db/${chainId}/${address}/init : timestamp
// db/${chainId}/${address}/seed : 32 bytes (no encoding)
// db/${chainId}/${address}/${pubkey}/log : JSON lines of log entries
//
// the log is an append-only record of user actions
// log entries have this format:
// { type: "setFeeRecipient" | "setGraffiti" | "setEnabled" | "keygen" | "exit"
// , time: timestamp
// , data: address | string | bool | number | undefined
// }
//
// environment variables
// CHAIN
// COMMAND
// ADDRESS
// PUBKEY
// DATA
// INDEX

const commands = ['init', 'keygen', 'setFeeRecipient', 'setGraffiti', 'setEnabled', 'keystore', 'exit', 'test']

if (!commands.includes(process.env.COMMAND)) {
  throw new Error(`Unrecognised command ${process.env.COMMAND}. Wanted: ${commands.join(' | ')}`)
}

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
    const seedBytes = ethers.getBytes(seed)
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
  const hexPubkey = ethers.hexlify(pubkey)
  if (hexPubkey == expectedPubkey)
    console.log(`Test pubkey passed`)
  else {
    throw new Error(`Test pubkey failed: Got ${pubkey} i.e. ${hexPubkey} instead of ${expectedPubkey}`)
  }
  process.exit()
}

const address = ethers.getAddress(process.env.ADDRESS)

const getTimestamp = () => Math.floor(Date.now() / 1000)

if (process.env.COMMAND == 'init') {
  const dirPath = `db/${chainId}/${address}`
  mkdirSync(dirPath, {recursive: true})
  writeFileSync(`${dirPath}/init`, getTimestamp().toString(), {flag: 'wx'})
  writeFileSync(`${dirPath}/seed`, randomBytes(32), {flag: 'wx'})
  process.exit()
}

else if (process.env.COMMAND == 'keygen') {
  const dirPath = `db/${chainId}/${address}`
  const seed = new Uint8Array(readFileSync(`${dirPath}/seed`))
  const prefixKey = getPrefixKey(seed)
  const startIndex = parseInt(process.env.INDEX) || 0
  let index = startIndex, sk, pubkey, keyPath
  while (true) {
    ({signing: sk} = getValidatorKeys({prefixKey}, index))
    pubkey = ethers.hexlify(pubkeyFromPrivkey(sk))
    keyPath = `${dirPath}/${pubkey}`
    if (existsSync(`${keyPath}/log`)) index++
    else break
  }
  const log = {type: 'keygen', time: getTimestamp(), data: index}
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
      if (type != 'keygen')
        throw new Error(`No keygen in first line of log ${line}`)
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

  if (!existsSync(`${dirPath}/${ethers.hexlify(pubkey)}/log`))
    throw new Error(`Key at ${index} not generated`)

  const ksp = generateKeystore({sk, pubkey, path})

  console.log(JSON.stringify(ksp))
  process.exit()
}

else {
  console.error(`Not implemented yet: ${process.env.COMMAND}`)
  process.exit(1)
}
