import { errorPrefix } from './lib.js'
process.setUncaughtExceptionCaptureCallback((e) => console.error(`${errorPrefix}${e.message}\n` + e.stack));

import { randomSeed, privkeyFromPath, pubkeyFromPrivkey, generateKeystore, toHex } from './sig.js'
import { bls12_381 } from '@noble/curves/bls12-381'
import { ensureDirs, gitCheck, gitPush, workDir, chainIds, addressRegExp, logFunction } from './lib.js'
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'node:fs'
import { createServer } from 'node:net'

// Override stdout and stderr message output with time and type prefix
for (const level of ['debug', 'info', 'warn', 'error']) logFunction(level);

console.info("Starting server");

ensureDirs();

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
  console.debug("Got new connection");

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
    console.error(`Got error ${e}`);
    stream.write(e)
    console.error("Closing connection");
    stream.end()
  })

  stream.on('close', function (had_error) {
    if(had_error) {
      console.error("Connection closed unexpectedly.");
    }
    stream.end()
  })

  function readLine(variable) {
    if (inputLines.length < 1) {
      throw new Error(`readLine called for ${variable}, but no more lines to read!`)
    }
    console.debug(`read line for ${variable}`);
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
      console.error(`Could not find chainId ${chainId} in chainIds list:`);
      console.error(chainIds);
      throw new Error('invalid chainId')
    }

    const address = readLine('ADDRESS')
    if (!addressRegExp.test(address))
      throw new Error('invalid address')

    const chainPath = `${workDir}/${chainId}`
    const seedPath = `${chainPath}/${address}`

    const command = readLine('COMMAND')

    if (command == 'generate') {
      console.debug('Handling [generate] request.');
      if (existsSync(seedPath)) {
        console.debug(`Seed path [${seedPath}] already exists.`);
        return 'exists';
      } else {
        console.info('The seedPath doesn\'t exist yet, creating it now.');
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
        console.info(`Seed path [${seedPath}] created.`);
        return 'created';
      }
    }
    else {
      const seed = readFileSync(seedPath)
      const path = readLine('KEYPATH')
      console.debug(privkeyFromPath);
      const sk = privkeyFromPath(seed, path)
      switch (command) {
        case 'pubkey': {
          console.debug('Handling [pubkey] request.');
          const pk = pubkeyFromPrivkey(sk)
          console.debug('Found pubkey from private key: ', `0x${toHex(pk)}`);
          return `0x${toHex(pk)}`;
          break
        }
        case 'keystore': {
          console.debug('Handling [keystore] request.');
          const pubkey = pubkeyFromPrivkey(sk)
          const password = readLine('KEYPASS')
          return JSON.stringify(generateKeystore({sk, path, pubkey, password}));
          break
        }
        case 'sign': {
          console.debug('Handling [sign] request.');
          const messageHex = readLine('MESSAGE')
          console.debug(messageHex);
          if (!messageHex.startsWith('0x')) throw new Error('invalid message')
          const message = Buffer.from(messageHex.slice(2), 'hex')
          const htfEthereum = {DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'}
          console.debug(`Signing ${message} with ${sk} and ${htfEthereum}.`);
          const sig = bls12_381.sign(message, sk, htfEthereum)
          console.debug(`Got sig ${sig}.`);
          return `0x${toHex(sig)}`;
          break
        }
        default:
          throw new Error('invalid command')
      }
    }
  }
}).listen(PORT);
