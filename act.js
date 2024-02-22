import { workDir, gitCheck, readJSONL } from './lib.js'
import { readFileSync, readdirSync } from 'node:fs'
import { createInterface } from 'node:readline'

const beaconUrl = process.env.BN || 'http://localhost:5052'

// {chainId: {pubkey: {url, enabled, feeRecipient, graffiti, status}, ...}, ...}
async function computeVcState(vcsConfig) {
  const vcState = {}
  for (const [chainId, vcs] of Object.entries(vcsConfig)) {
    if (chainId in vcState) throw new Error(`Duplicate chainId ${chainId}`)
    const validatorsByPubkey = {}
    vcState[chainId] = validatorsByPubkey
    for (const {url, authToken} of vcs) {
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
          const json = await res.json()
          validator.feeRecipient = json.data.ethaddress
        }
        {
          const res = await fetch(`${url}/eth/v1/validator/${voting_pubkey}/graffiti`, {headers})
          const json = await res.json()
          validator.graffiti = json.data.graffiti
        }
        {
          const res = await fetch(`${beaconUrl}/eth/v1/beacon/states/finalized/validators/${voting_pubkey}`)
          const json = await res.json()
          validator.status = json.data.status
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

function computeDiscrepancy(vcState) {
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
      if (!pubkey) continue
      srvPubkeys.push(pubkey)
      const validator = validatorsByPubkey[pubkey]
      if (!validator) {
        discrepancies.push({chainId, pubkey, issue: 'exists', srv: true, vc: false})
        continue
      }
      const logPath = `${chainDir}/${pubkeyWithAddress}`
      const reverseLogs = readJSONL(logPath).toReversed()
      const srvEnabled = reverseLogs.find(({type}) => type == 'SetEnabled')?.enabled
      const srvFeeRecipient = reverseLogs.find(({type}) => type == 'SetFeeRecipient')?.feeRecipient
      const srvGraffiti = reverseLogs.find(({type}) => type == 'SetGraffiti')?.graffiti
      const srvExited = reverseLogs.find(({type}) => type == 'Exit')
      const base = {chainId, pubkey, url: validator.url}
      if (validator.enabled !== srvEnabled)
        discrepancies.push({...base, issue: 'enabled', srv: srvEnabled, vc: validator.enabled})
      if (validator.feeRecipient !== srvFeeRecipient)
        discrepancies.push({...base, issue: 'feeRecipient', srv: srvFeeRecipient, vc: validator.feeRecipient})
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
let discrepancy

function ensureVcsConfig() {
  if (!vcsConfig)
    vcsConfig = JSON.parse(readFileSync('vcs.json'))
}

async function ensureVcState() {
  ensureVcsConfig()
  if (!vcState)
    vcState = await computeVcState(vcsConfig)
}

createInterface({input: process.stdin}).on('line', async (line) => {
  switch (line) {
    case 'd':
      console.log(`Got request to print discrepancies`)
      await ensureVcState()
      if (!vcState) throw new Error(`Failed to produce vcState`)
      console.log(`Discrepancies:`)
      computeDiscrepancy(vcState).forEach(x =>
        console.log(JSON.stringify(x))
      )
      console.log(`End of Discrepancies`)
      break
    case 'c':
      console.log(`Got request to refresh config`)
      vcsConfig = undefined
      ensureVcsConfig()
      break
    case 's':
      console.log(`Got request to refresh state`)
      vcState = undefined
      await ensureVcState()
      break
    default:
      console.warn(`Unknown command '${line}'`)
  }
})

// TODO: alert + act on any discrepancies
