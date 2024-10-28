# Run db API services locally

[!CAUTION]
Only run your local dev environment using a test net (Holesky)

This project provides a `compose.yaml` configuration which allows you to easily spin up the db services.
A few steps are required to set this up. These steps are described below.

## Create a config for act

The `act` service requires a `vcs.json` config file. This file should provide validator endpoints and auth tokens for each chain.

Example:

`vcs.json`
```json
{
    "17000": [
        {
            "url": "http://validator:5063",
            "authToken": "[Token can be found in ~/.rocketpool/data/validators/lighthouse/validators/api-token.txt]"
        }
    ]
}
```

## Create a .env file

You can copy `.env-example` to `.env` and change the variables where needed.

## Run docker compose

### Start the services in the background
```bash
docker compose --profile db up -d
```

### Follow logs
```bash
docker compose --profile db logs -f
```

### Rebuild image after code changes

You can force a docker rebuild by running the following docker compose commands:

**srv**
```bash
docker compose build srv
```

**act**
```bash
docker compose build act
```

## Additional notes

Currently, the db services only work with Lighthouse as validator backend. The Lighthouse validator should be started with at least the following flags:
```bash
--http-port 5063 --unencrypted-http-transport --http --http-address 0.0.0.0
```

You can change the http-port and http-address according to your needs.
