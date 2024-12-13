import { errorPrefix } from './lib.js'
process.setUncaughtExceptionCaptureCallback((e) => console.log(`${errorPrefix}${e.message}`))

import { randomSeed, privkeyFromPath, pubkeyFromPrivkey, generateKeystore, toHex } from './sig.js'
import { bls12_381 } from '@noble/curves/bls12-381'
import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRegExp } from './lib.js'
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'node:fs'
import { createServer } from 'node:net'

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

const [HOST, PORT] = process.env.PRV_HOST.split(':')

createServer((stream) => {
  console.log("Got new connection")

  const inputLines = []
  let buffer = ''

  stream.on('data', function (data) {
    buffer += data.toString();
  })

  stream.on('end', function () {
    buffer.split('\n').forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine) inputLines.push(trimmedLine); // Ignore empty lines
    });
    stream.write(handleRequest());
    stream.end()
  })

  stream.on('error', function (e) {
    console.log(`Got error ${e}`)
    stream.write(e)
    console.log("Closing connection")
    stream.end()
  })

  stream.on('close', function (had_error) {
    if(had_error) {
      console.log("Connection closed unexpectedly.")
    }
    stream.end()
  })

  function readLine(variable) {
    if (inputLines.length < 1) {
      throw new Error(`readLine called for ${variable}, but no more lines to read!`)
    }
    const prefix = `${variable} = `
    const line = inputLines.shift()
    if (!(line && line.startsWith(prefix))) {
      throw new Error(`missing ${variable}`)
    }
    return line.slice(prefix.length)
  }

  function handleRequest() {
    const chainId = readLine('CHAINID')
    if (!(chainId in chainIds)) {
      console.log(`Could not find chainId ${chainId} in chainIds list:`)
      console.log(chainIds)
      throw new Error('invalid chainId')
    }

    const address = readLine('ADDRESS')
    if (!addressRegExp.test(address))
      throw new Error('invalid address')

    const chainPath = `${workDir}/${chainId}`
    const seedPath = `${chainPath}/${address}`

    const command = readLine('COMMAND')

    if (command == 'generate') {
      if (existsSync(seedPath))
        return 'exists';
      else {
        mkdirSync(chainPath, {recursive: true})
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
        return 'created';
      }
    }
    else {
      const seed = readFileSync(seedPath)
      const path = readLine('KEYPATH')
      const sk = privkeyFromPath(seed, path)
      switch (command) {
        case 'pubkey': {
          const pk = pubkeyFromPrivkey(sk)
          return `0x${toHex(pk)}`;
          break
        }
        case 'keystore': {
          const pubkey = pubkeyFromPrivkey(sk)
          const password = readLine('KEYPASS')
          return JSON.stringify(generateKeystore({sk, path, pubkey, password}));
          break
        }
        case 'sign': {
          const messageHex = readLine('MESSAGE')
          if (!messageHex.startsWith('0x')) throw new Error('invalid message')
          const message = Buffer.from(messageHex.slice(2), 'hex')
          const htfEthereum = {DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'}
          const sig = bls12_381.sign(message, sk, htfEthereum)
          return `0x${toHex(sig)}`;
          break
        }
        default:
          throw new Error('invalid command')
      }
    }
  }
}).listen(PORT);
