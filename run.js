import { randomBytes } from 'node:crypto'
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'node:fs'
import { hexToBytes, toHex } from "ethereum-cryptography/utils.js";

// old code below

/*
const getTimestamp = () => Math.floor(Date.now() / 1000)

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
