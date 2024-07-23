import { workDir, gitCheck, readJSONL, pathsFromIndex, chainIds, prv } from './lib.js'
import { readFileSync, readdirSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { randomInt } from 'node:crypto'

const authTokens = new Map()

const checkStatus = async (desired, res, path) => {
  const correct = res.status === desired
  if (!correct)
    console.error(`Request failed for ${path}: ${res.status} ${res.statusText}: ${JSON.stringify(await res.json())}`)
  return correct
}

const hexDigitsRegExp = /^0x(?<content>(?:[0-9a-f][0-9a-f])*?)0*$/

// {chainId: {pubkey: {url, enabled, feerecipient, graffiti, status}, ...}, ...}
async function computeVcState(vcsConfig) {
  const vcState = {}
  for (const [chainId, vcs] of Object.entries(vcsConfig)) {
    if (chainId in vcState) throw new Error(`Duplicate chainId ${chainId}`)
    const network = chainIds[chainId]
    if (!network) throw new Error(`Unknown chainId ${chainId}`)
    const beaconHostPort = process.env[`${network.toUpperCase()}_BN`]
    if (!beaconHostPort) throw new Error(`No beacon node URL environment variable for ${chainId}`)
    const beaconUrl = `http://${beaconHostPort}`
    const validatorsByPubkey = {}
    vcState[chainId] = validatorsByPubkey
    for (const {url, authToken} of vcs) {
      authTokens.set(url, authToken)
      const headers = {'Authorization': `Bearer ${authToken}`}
      const res = await fetch(`${url}/lighthouse/validators`, {headers})
      const json = await res.json()
      for (const {enabled, voting_pubkey} of json.data) {
        if (voting_pubkey in validatorsByPubkey)
          throw new Error(`Duplicate pubkey ${voting_pubkey}: ${url} and ${validatorsByPubkey[voting_pubkey].url}`)
        const validator = {url, enabled}
        validatorsByPubkey[voting_pubkey] = validator
        {
          const path = `${url}/eth/v1/validator/${voting_pubkey}/feerecipient`
          const res = await fetch(path, {headers})
          if (await checkStatus(200, res, path)) {
            const json = await res.json()
            validator.feerecipient = json.data.ethaddress.toLowerCase()
          }
        }
        {
          const path = `${url}/eth/v1/validator/${voting_pubkey}/graffiti`
          const res = await fetch(path, {headers})
          if (await checkStatus(200, res, path)) {
            const json = await res.json()
            const graffitiHex = hexDigitsRegExp.exec(json.data.graffiti)?.groups.content || ''
            validator.graffiti = Buffer.from(graffitiHex, 'hex').toString()
          }
        }
        {
          const path = `${beaconUrl}/eth/v1/beacon/states/finalized/validators/${voting_pubkey}`
          const res = await fetch(path)
          if (await checkStatus(200, res, path)) {
            const json = await res.json()
            validator.status = json.data.status
          }
        }
      }
    }
  }
  return vcState
}

const nullAddress = '0x'.padEnd(42, '0')

async function getEffectiveFeeRecipient(rawFeeRecipient, chainId, nodeAddress) {
  if (rawFeeRecipient !== nullAddress)
    return rawFeeRecipient
  const res = await fetch(`https://fee.vrün.com/${chainId}/${nodeAddress}/rp-fee-recipient`)
  // TODO: checkStatus?
  return await res.json().then(a => a.toLowerCase())
}

const exitedStatuses = ['exited_unslashed', 'exited_slashed', 'withdrawal_possible', 'withdrawal_done']

async function computeDiscrepancies(vcState) {
  gitCheck(['status', '--porcelain'], workDir, '', 'work directory not clean')
  const discrepancies = []
  const chainIds = readdirSync(workDir)
  for (const chainId of chainIds) {
    if (chainId === '.git') continue
    const srvPubkeys = []
    const validatorsByPubkey = vcState[chainId] || {}
    const chainDir = `${workDir}/${chainId}`
    const pubkeysWithAddresses = readdirSync(chainDir, {recursive: true})
    for (const pubkeyWithAddress of pubkeysWithAddresses) {
      const [address, pubkey] = pubkeyWithAddress.split('/')
      if (address == 'a' || address == 'c' || !pubkey) continue
      srvPubkeys.push(pubkey)
      const logPath = `${chainDir}/${pubkeyWithAddress}`
      const reverseLogs = readJSONL(logPath).toReversed()
      const index = reverseLogs.find(({type}) => type == 'CreateKey').index
      const validator = validatorsByPubkey[pubkey]
      if (!validator) {
        discrepancies.push({chainId, address, index, pubkey, issue: 'exists', srv: true, vc: false})
        continue
      }
      if (exitedStatuses.includes(validator.status)) continue
      const srvEnabled = reverseLogs.find(({type}) => type == 'SetEnabled')?.enabled
      const rawFeeRecipient = reverseLogs.find(({type}) => type == 'SetFeeRecipient')?.feeRecipient
      const srvFeeRecipient = await getEffectiveFeeRecipient(rawFeeRecipient, chainId, address)
      const srvGraffiti = reverseLogs.find(({type}) => type == 'SetGraffiti')?.graffiti
      const base = {chainId, address, index, pubkey, url: validator.url}
      if (validator.enabled !== srvEnabled)
        discrepancies.push({...base, issue: 'enabled', srv: srvEnabled, vc: validator.enabled})
      if (validator.feerecipient !== srvFeeRecipient)
        discrepancies.push({...base, issue: 'feeRecipient', srv: srvFeeRecipient, vc: validator.feerecipient})
      if (validator.graffiti !== srvGraffiti)
        discrepancies.push({...base, issue: 'graffiti', srv: srvGraffiti, vc: validator.graffiti})
    }
    for (const pubkey of Object.keys(validatorsByPubkey))
      if (!srvPubkeys.includes(pubkey))
        discrepancies.push({chainId, pubkey, issue: 'exists', srv: false, vc: true})
  }
  return discrepancies
}

let vcsConfig
let vcState
let discrepancies

function ensureVcsConfig() {
  if (!vcsConfig)
    vcsConfig = JSON.parse(readFileSync('vcs.json'))
}

async function ensureVcState() {
  ensureVcsConfig()
  if (!vcState)
    vcState = await computeVcState(vcsConfig)
}

async function ensureDiscrepancies() {
  await ensureVcState()
  if (!discrepancies)
    discrepancies = await computeDiscrepancies(vcState)
}

async function fixDiscrepancy(i) {
  const d = discrepancies[i]
  console.log(`Fixing discrepancy ${i}: ${JSON.stringify(d)}`)
  const headers = {
    'Authorization': `Bearer ${authTokens.get(d.url)}`,
    'Content-Type': 'application/json'
  }
  const logPrefix = `${d.chainId}:${d.pubkey}: `
  switch (d.issue) {
    case 'exists':
      if (d.vc)
        console.warn(`${logPrefix}In VC but not srv, ignoring...`)
      else {
        console.log(`${logPrefix}Importing keystore into VC`)
        await ensureVcState()
        const vcs = vcsConfig[d.chainId] || []
        const validatorsByPubkey = vcState[d.chainId] || {}
        const pubkeysPerUrl = {}
        vcs.forEach(({url}) => pubkeysPerUrl[url] = 0)
        for (const [pubkey, {url}] of Object.entries(validatorsByPubkey))
          pubkeysPerUrl[url]++
        const [[leastFullVC, ]] = Object.entries(pubkeysPerUrl).toSorted(([, a], [, b]) => a - b)
        if (!leastFullVC) {
          console.error(`No VC available, cannot import keystore`)
          break
        }
        const authToken = authTokens.get(leastFullVC)
        if (!authToken) {
          console.error(`Auth token missing for ${leastFullVC}, cannot import keystore`)
          break
        }
        headers['Authorization'] = `Bearer ${authToken}`
        const passwordChars = []
        for (const i of Array(randomInt(16, 49)).keys())
          passwordChars.push(String.fromCodePoint(randomInt(33, 127)))
        const password = passwordChars.join('')
        const {signing: path} = pathsFromIndex(d.index)
        const keystore = prv('keystore', {chainId: d.chainId, address: d.address, path, password})
        const body = JSON.stringify({keystores: [keystore], passwords: [password]})
        const url = `${leastFullVC}/eth/v1/keystores`
        await checkStatus(200,
          await fetch(url, {headers, method: 'POST', body}),
          url)
      }
      break
    case 'enabled': {
      console.log(`${logPrefix}Setting VC enabled to ${d.srv}`)
      const path = `${d.url}/lighthouse/validators/${d.pubkey}`
      await checkStatus(200,
        await fetch(path,
          {headers, method: 'PATCH', body: `{"enabled": ${d.srv}}`}),
        path)
      break
    }
    case 'feeRecipient': {
      console.log(`${logPrefix}Changing VC feeRecipient from ${d.vc} to ${d.srv}`)
      const path = `${d.url}/eth/v1/validator/${d.pubkey}/feerecipient`
      await checkStatus(202,
        await fetch(path,
          {headers, method: 'POST', body: `{"ethaddress": "${d.srv}"}`}),
        path)
      break
    }
    case 'graffiti': {
      console.log(`${logPrefix}Changing VC graffiti from ${d.vc} to ${d.srv}`)
      const path = `${d.url}/eth/v1/validator/${d.pubkey}/graffiti`
      await checkStatus(202,
        await fetch(path,
          {headers, method: 'POST', body: JSON.stringify({graffiti: d.srv})}),
        path)
      break
    }
    default:
      console.error(`Unknown discrepancy '${d.issue}'`)
  }
}

createInterface({input: process.stdin}).on('line', async (line) => {
  switch (line) {
    case 'c':
      console.log(`Refreshing config`)
      vcsConfig = undefined
      ensureVcsConfig()
    case 's':
    case 'r':
    case 'rf':
      console.log(`Refreshing state`)
      vcState = undefined
      await ensureVcState()
      if (!line.startsWith('r')) break
    case 'd':
      console.log(`Refreshing discrepancies`)
      discrepancies = undefined
    case 'p':
      console.log(`Printing discrepancies`)
      await ensureDiscrepancies()
      console.log(`Discrepancies:`)
      discrepancies.forEach((x, i) => console.log(`${i}: ${JSON.stringify(x)}`))
      console.log(`End of Discrepancies`)
      if (!line.endsWith('f')) break
    case 'f':
      await Promise.all(Array.from(discrepancies.keys()).map(fixDiscrepancy))
      break
    default:
      const [f, i] = line.split(' ', 2)
      if (f === 'f' && 0 <= parseInt(i) && i < discrepancies?.length)
        await fixDiscrepancy(i)
      else
        console.warn(`Unknown command '${line}'`)
  }
})
