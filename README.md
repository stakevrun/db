# srv: vrün HTTP API

## GET requests

All the GET requests return `application/json` content.

- `GET /<chainId>/<address>/acceptance`
Returns:
```
{timestamp: number, declaration: string, signature: string}
```
acceptance of the terms of service signed by `address`, where `signature` is an
EIP-712 signature (represented as a 0x-prefixed hexstring) over the
`AcceptTermsOfService` structure described further down.

- `GET /<chainId>/<address>/nextindex`
Returns: number - the next unused key index for `address`.

- `GET /<chainId>/<address>/pubkey/<index>`
Returns: string - 0x-prefixed hexstring of the public key at `index` for
`address`.

- `GET /<chainId>/<address>/<pubkey>/length?type`
Returns: number - the number of log entries for `address` and `pubkey` whose
type matches the regular expression given by `type` (or all entries if `type`
is omitted).

- `GET /<chainId>/<address>/<pubkey>/logs?type&start&end`
Returns: `[<log>...]` - log entries whose type matches `type` (all if omitted),
with `start` and `end` interpreted as in `Array.prototype.slice`, with the
earliest matching logs first.

- `GET /<chainId>/<address>/credit/length`
Returns: number - the number of log entries for `address` whose type is
`CreditAccount`.

- `GET /<chainId>/<address>/credit/logs?hash&reason&start&end`
Returns: `[<log>...]` - `CreditAccount` log entries whose `transactionHash`and
`reason` match `hash` (exact) and `reason` (regular expression) (all if
omitted), with `start` and `end` interpreted as in `Array.prototype.slice`,
with the earliest matching logs first.

## PUT/POST requests

- `PUT /<chainId>/<address>`
- `POST /<chainId>/<address>/<index>`
- `POST /<chainId>/<address>/batch`
- `POST /<chainId>/<address>/credit`

The body content-type should be `application/json`.

The body should be JSON in the following format:
```
{type: string, data: <object>, signature: string}
```
or
```
{type: string, data: <object>, signature: string, indices: number[]}
```
where `signature` is an [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
signature over `type{...data}` encoded as a compact 0x-prefixed hexstring, with
`EIP712Domain = {name: "vrün", version: "1", chainId: <chainId>}`.

The possible data objects (instructions) are given below.`PUT` is used for
`AcceptTermsOfService` and `CreateKey`. `POST` is used for the others.

The `batch` route (with `indices` included in the body) is used exactly when
the data object has a `pubkeys` component, and the indices should correspond to
the `pubkeys` if so. Otherwise the `index` in the route should correspond to the
`pubkey` (if any) in the data object.

The `credit` route is used exactly when the type is `CreditAccount`. In this
case, the `nodeAccount` in the data should match the `address` in the route,
and the signature must be from a Vrün administrator account.

```
struct AcceptTermsOfService {
  string declaration;
}

struct CreateKey {
  uint256 index;
}

struct GetDepositData {
  bytes pubkey;
  bytes32 withdrawalCredentials;
  uint256 amountGwei;
}

struct GetPresignedExit {
  bytes pubkey;
  uint256 validatorIndex;
  uint256 epoch;
}

struct SetFeeRecipient {
  uint256 timestamp;
  bytes[] pubkeys;
  address feeRecipient;
}

struct SetGraffiti {
  uint256 timestamp;
  bytes[] pubkeys;
  string graffiti;
}

struct SetEnabled {
  uint256 timestamp;
  bytes[] pubkeys;
  bool enabled;
}

struct AddValidators {
  uint256 timestamp;
  uint256 firstIndex;
  uint256 amountGwei;
  address feeRecipient;
  string graffiti;
  address[] withdrawalAddresses;
}

struct CreditAccount {
  uint256 timestamp;
  address nodeAccount;
  uint256 numDays;
  bool decreaseBalance;
  uint256 chainId;
  bytes32 transactionHash;
  string reason;
}
```

When encoding these as JSON objects, we use strings suitable for `BigInt` for
`uint256`, and 0x-prefixed lowercase hexstrings for `bytes` and `address`.

We check the `chainId` in the URL matches the EIP712Domain `chainId`.

Successful responses will have status 200 or 201 and an empty body or an
`application/json` body for the following requests:

- `CreateKey` Returns: `{index: number, pubkey: string}`
where pubkey is the 0x-prefixed hexstring encoding the created key's pubkey
and index is the index for that pubkey.

- `GetDepositData` Returns: `{depositDataRoot: string, signature: string}`
where `depositDataRoot` is a 0x-prefixed hexstring of 32 bytes, and
`signature` is a 0x-prefixed hexstring encoding a signature over
`depositDataRoot`.

- `GetPresignedExit` Returns: a <a href=https://ethereum.github.io/keymanager-APIs/?urls.primaryName=dev#/Voluntary%20Exit/signVoluntaryExit>SignedVoluntaryExitResponse</a>.

- `AddValidators` Returns: `{<pubkey>: {depositDataRoot: string, signature: string}, ...}`,
that is, a response similar to `GetDepositData` for each pubkey.

Any issues with processing the body (wrong content-type, bad signature,
malformed instruction, invalid instruction) will get a 40x response with a
plain text error message body.

Any errors raised in processing the request will be relayed back in a plain
text body with a 500 response.
