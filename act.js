import { workDir, gitCheck, readJSONL, pathsFromIndex, chainIds, prv } from './lib.js'
import { readFileSync, readdirSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { randomInt } from 'node:crypto'

const authTokens = new Map()

const checkStatus = async (desired, res) => {
  const correct = res.status === desired
  if (!correct)
    console.error(`Request failed, ${res.status} ${res.statusText}: ${JSON.stringify(await res.json())}`)
  return correct
}

const hexDigitsRegExp = /^0x(?<content>[0-9a-f]*?)0*$/

// {chainId: {pubkey: {url, enabled, feerecipient, graffiti, status}, ...}, ...}
async function computeVcState(vcsConfig) {
  const vcState = {}
  for (const [chainId, vcs] of Object.entries(vcsConfig)) {
    if (chainId in vcState) throw new Error(`Duplicate chainId ${chainId}`)
    const network = chainIds[chainId]
    if (!network) throw new Error(`Unknown chainId ${chainId}`)
    const bnPorts = readFileSync(`/usr/share/vrün/bnports-${network}`, 'utf8').split('\n')
    if (!bnPorts?.length) throw new Error(`No beacon node ports for ${chainId}`)
    const beaconUrl = `http://localhost:${bnPorts[0]}`
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
          const res = await fetch(`${url}/eth/v1/validator/${voting_pubkey}/feerecipient`, {headers})
          if (await checkStatus(200, res)) {
            const json = await res.json()
            validator.feerecipient = json.data.ethaddress
          }
        }
        {
          const res = await fetch(`${url}/eth/v1/validator/${voting_pubkey}/graffiti`, {headers})
          if (await checkStatus(200, res)) {
            const json = await res.json()
            const graffitiHex = hexDigitsRegExp.exec(json.data.graffiti)?.groups.content || ''
            validator.graffiti = Buffer.from(graffitiHex, 'hex').toString()
          }
        }
        {
          const res = await fetch(`${beaconUrl}/eth/v1/beacon/states/finalized/validators/${voting_pubkey}`)
          if (await checkStatus(200, res)) {
            const json = await res.json()
            validator.status = json.data.status
          }
        }
      }
    }
  }
  return vcState
}

const exitStatuses = [
  'active_exiting',
  'exited_unslashed',
  'withdrawal_possible',
  'withdrawal_done'
]

function computeDiscrepancies(vcState) {
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
      if (address == 'a' || !pubkey) continue
      srvPubkeys.push(pubkey)
      const logPath = `${chainDir}/${pubkeyWithAddress}`
      const reverseLogs = readJSONL(logPath).toReversed()
      const index = reverseLogs.find(({type}) => type == 'CreateKey').index
      const validator = validatorsByPubkey[pubkey]
      if (!validator) {
        discrepancies.push({chainId, address, index, pubkey, issue: 'exists', srv: true, vc: false})
        continue
      }
      const srvEnabled = reverseLogs.find(({type}) => type == 'SetEnabled')?.enabled
      const srvFeeRecipient = reverseLogs.find(({type}) => type == 'SetFeeRecipient')?.feerecipient
      const srvGraffiti = reverseLogs.find(({type}) => type == 'SetGraffiti')?.graffiti
      const srvExited = reverseLogs.find(({type}) => type == 'Exit')
      const base = {chainId, address, index, pubkey, url: validator.url}
      if (validator.enabled !== srvEnabled)
        discrepancies.push({...base, issue: 'enabled', srv: srvEnabled, vc: validator.enabled})
      if (validator.feerecipient !== srvFeeRecipient)
        discrepancies.push({...base, issue: 'feeRecipient', srv: srvFeeRecipient, vc: validator.feerecipient})
      if (validator.graffiti !== srvGraffiti)
        discrepancies.push({...base, issue: 'graffiti', srv: srvGraffiti, vc: validator.graffiti})
      if (!srvExited == exitStatuses.includes(validator.status))
        discrepancies.push({...base, issue: 'exit', srv: srvExited, vc: validator.status})
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
    discrepancies = computeDiscrepancies(vcState)
}

createInterface({input: process.stdin}).on('line', async (line) => {
  switch (line) {
    case 'r':
    case 's':
      console.log(`Got request to refresh state`)
      vcState = undefined
      await ensureVcState()
      if (line != 'r') break
    case 'd':
      console.log(`Got request to refresh discrepancies`)
      discrepancies = undefined
    case 'p':
      console.log(`Got request to print discrepancies`)
      await ensureDiscrepancies()
      console.log(`Discrepancies:`)
      discrepancies.forEach((x, i) => console.log(`${i}: ${JSON.stringify(x)}`))
      console.log(`End of Discrepancies`)
      break
    case 'c':
      console.log(`Got request to refresh config`)
      vcsConfig = undefined
      ensureVcsConfig()
      break
    default:
      const [f, i] = line.split(' ', 2)
      if (f === 'f' && 0 <= parseInt(i) && i < discrepancies?.length) {
        const d = discrepancies[i]
        console.log(`Got request to fix discrepancy ${i}: ${JSON.stringify(d)}`)
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
              await checkStatus(200,
                await fetch(`${leastFullVC}/eth/v1/keystores`,
                  {headers, method: 'POST', body}))
            }
            break
          case 'enabled':
            console.log(`${logPrefix}Setting VC enabled to ${d.srv}`)
            await checkStatus(200,
              await fetch(`${d.url}/lighthouse/validators/${d.pubkey}`,
                {headers, method: 'PATCH', body: `{"enabled": ${d.srv}}`}))
            break
          case 'feeRecipient':
            console.log(`${logPrefix}Changing VC feeRecipient from ${d.vc} to ${d.srv}`)
            await checkStatus(202,
              await fetch(`${d.url}/eth/v1/validator/${d.pubkey}/feerecipient`,
                {headers, method: 'POST', body: `{"ethaddress": "${d.srv}"}`}))
            break
          case 'graffiti':
            console.log(`${logPrefix}Changing VC graffiti from ${d.vc} to ${d.srv}`)
            await checkStatus(202,
              await fetch(`${d.url}/eth/v1/validator/${d.pubkey}/graffiti`,
                {headers, method: 'POST', body: `{"graffiti": "${d.srv}"}`}))
            break
          case 'exit':
            console.log(`${logPrefix}Requested exit but status is ${d.vc}. Creating exit message...`)
            const res = await fetch(`${d.url}/eth/v1/validator/${d.pubkey}/voluntary_exit`,
              {headers, method: 'POST'})
            if (await checkStatus(200, res)) {
              const exitMessage = await res.json()
              console.log(`Produced exit message: ${JSON.stringify(exitMessage)}`)
              // TODO: broadcast to beacon node?
            }
            break
          default:
            console.error(`Unknown discrepancy '${d.issue}'`)
        }
      }
      else
        console.warn(`Unknown command '${line}'`)
  }
})
