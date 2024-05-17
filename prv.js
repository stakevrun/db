import { errorPrefix } from './lib.js'
process.setUncaughtExceptionCaptureCallback((e) => console.log(`${errorPrefix}${e.message}`))

import { randomSeed, privkeyFromPath, pubkeyFromPrivkey, generateKeystore, toHex } from './sig.js'
import { bls12_381 } from '@noble/curves/bls12-381'
import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRegExp } from './lib.js'
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'

ensureDirs()

// prv repository database layout:
// ${chainId}/${address} : 32 bytes (no encoding)

// prv: private key management
// takes stdin for input and produces output on stdout
// the input is lines of the form <VARIABLE> = <VALUE>, which must occur in the
// following order only including the variables relevant to the command:
// CHAINID = decimal string identifying the chain
// ADDRESS = hexstring indicating the seed's owner
// COMMAND = one of ( generate | pubkey | keystore | sign )
// KEYPATH = string indicating the path for key derivation
// KEYPASS = string to use as password for the keystore
// MESSAGE = hexstring of the data to sign
//
// generate: ensure the seed for ADDRESS exists, return 'created' or 'exists'
// pubkey:   return the pubkey (hexstring) for ADDRESS's key at KEYPATH
// keystore: return a JSON-encoded keystore for ADDRESS's key at KEYPATH (protected by KEYPASS)
// sign:     return signature (hexstring) for MESSAGE using ADDRESS's key at KEYPATH

const inputLines = []
for await (const line of createInterface({input: process.stdin}))
  inputLines.push(line)

const readLine = (variable) => {
  const prefix = `${variable} = `
  const line = inputLines.shift()
  if (!(line && line.startsWith(prefix)))
    throw new Error(`missing ${variable}`)
  return line.slice(prefix.length)
}

const chainId = readLine('CHAINID')
if (!(chainId in chainIds))
  throw new Error('invalid chainId')

const address = readLine('ADDRESS')
if (!addressRegExp.test(address))
  throw new Error('invalid address')

const chainPath = `${workDir}/${chainId}`
const seedPath = `${chainPath}/${address}`

const command = readLine('COMMAND')

if (command == 'generate') {
  if (existsSync(seedPath))
    console.log('exists')
  else {
    mkdirSync(chainPath)
    writeFileSync(seedPath, randomSeed(), {flag: 'wx'})
    gitCheck(['add', seedPath], workDir, '', 'failed to add seed')
    gitCheck(['diff', '--staged', '--name-status'], workDir,
      output => (
        !output.trimEnd().includes('\n') &&
        output.trimEnd().split(/\s+/).join() == `A,${chainId}/${address}`
      ),
      'unexpected diff adding seed'
    )
    gitPush(address, workDir)
    console.log('created')
  }
}
else {
  const seed = readFileSync(seedPath)
  const path = readLine('KEYPATH')
  const sk = privkeyFromPath(seed, path)
  switch (command) {
    case 'pubkey': {
      const pk = pubkeyFromPrivkey(sk)
      console.log(`0x${toHex(pk)}`)
      break
    }
    case 'keystore': {
      const pubkey = pubkeyFromPrivkey(sk)
      const password = readLine('KEYPASS')
      console.log(JSON.stringify(generateKeystore({sk, path, pubkey, password})))
      break
    }
    case 'sign': {
      const messageHex = readLine('MESSAGE')
      if (!messageHex.startsWith('0x')) throw new Error('invalid message')
      const message = Buffer.from(message.slice(2), 'hex')
      const htfEthereum = {DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'}
      const sig = bls12_381.sign(message, sk, htfEthereum)
      console.log(`0x${toHex(sig)}`)
      break
    }
    default:
      throw new Error('invalid command')
  }
}
