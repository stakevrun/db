import { errorPrefix } from './lib.js'
process.setUncaughtExceptionCaptureCallback((e) => console.log(`${errorPrefix}${e.message}`))

import { randomSeed, privkeyFromPath, pubkeyFromPrivkey, generateKeystore, toHex } from './sig.js'
import { bls12_381 } from '@noble/curves/bls12-381'
import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRegExp } from './lib.js'
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'node:fs'

ensureDirs()

// prv repository database layout:
// ${chainId}/${address} : 32 bytes (no encoding)

// prv: private key management
// takes environment variables and stdin for input (raw bytes) and produces
// output on stdout
// input variables:
// COMMAND = one of ( generate | pubkey | keystore | sign )
// CHAINID = decimal string identifying the chain
// ADDRESS = hexstring indicating the seed's owner
// KEYPATH = string indicating the path for key derivation
// KEYPASS = string to use as password for the keystore
//
// generate: ensure the seed for ADDRESS exists, return 'created' or 'exists'
// pubkey:   return the pubkey (hexstring) for ADDRESS's key at KEYPATH
// keystore: return a JSON-encoded keystore for ADDRESS's key at KEYPATH (protected by KEYPASS)
// sign:     return signature (hexstring) for input data using ADDRESS's key at KEYPATH

if (!addressRegExp.test(process.env.ADDRESS))
  throw new Error('invalid address')

if (!(process.env.CHAINID in chainIds))
  throw new Error('invalid chainId')

const address = process.env.ADDRESS
const chainId = process.env.CHAINID
const chainPath = `${workDir}/${chainId}`
const seedPath = `${chainPath}/${address}`

if (process.env.COMMAND == 'generate') {
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
  if (!process.env.KEYPATH) throw new Error('missing keypath')
  const sk = privkeyFromPath(seed, process.env.KEYPATH)
  switch (process.env.COMMAND) {
    case 'pubkey': {
      const pk = pubkeyFromPrivkey(sk)
      console.log(`0x${toHex(pk)}`)
      break
    }
    case 'keystore': {
      const pubkey = pubkeyFromPrivkey(sk)
      const path = process.env.KEYPATH
      const password = process.env.KEYPASS
      console.log(JSON.stringify(generateKeystore({sk, path, pubkey, password})))
      break
    }
    case 'sign': {
      const sig = bls12_381.sign(readFileSync(process.stdin.fd), sk)
      console.log(`0x${toHex(sig)}`)
      break
    }
    default:
      throw new Error('invalid command')
  }
}
