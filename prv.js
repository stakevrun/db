process.setUncaughtExceptionCaptureCallback((e) => {
  console.log(`error: ${e.message}`)
})

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
//
// generate: ensure the seed for ADDRESS exists, return 'created' or 'exists'
// pubkey:   return the pubkey (hexstring) for ADDRESS's key at KEYPATH
// keystore: return a JSON-encoded keystore for ADDRESS's key at KEYPATH
// sign:     return signature (hexstring) for input data using ADDRESS's key at KEYPATH

if (!addressRegExp.test(process.env.ADDRESS))
  throw new Error('invalid address')

if (!(process.env.CHAINID in chainIds))
  throw new Error('invalid chainId')

const address = process.env.ADDRESS
const chainId = process.env.CHAINID
const chainPath = `${workDir}/${chainId}`
const seedPath = `${chainPath}/${address}`

switch (process.env.COMMAND) {
  case 'generate': {
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
    break
  }
  case process.env.COMMAND:
    const seed = readFileSync(seedPath)
    const sk = privkeyFromPath(seed, process.env.KEYPATH)
  case 'pubkey': {
    const pk = pubkeyFromPrivkey(sk)
    console.log(`0x${toHex(pk)}`)
    break
  }
  case 'keystore': {
    const pubkey = pubkeyFromPrivkey(sk)
    const path = process.env.KEYPATH
    console.log(JSON.stringify(generateKeystore({sk, path, pubkey})))
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
