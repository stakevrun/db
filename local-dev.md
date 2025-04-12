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
    "560048": [
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

### Start the proxy service
If you want to be able to connect to the APIs from a local running frontend, you can spin up the proxy service provided by Traefik
```bash
docker compose --profile proxy up -d
```
You can now query the db service on port 80 through the reverse proxy
```bash
curl http://localhost/admins
```

### Rebuild image after code changes

You can force a docker rebuild by running the following docker compose commands:

**srv**
```bash
docker compose build srv
# optional, restart the srv container to use the newly built docker image
docker compose --profile srv up -d
```

**act**
```bash
docker compose build act
# optional, restart the act container to use the newly built docker image
docker compose --profile act up -d
```

**prv**
```bash
docker compose build prv
# optional, restart the prv container to use the newly built docker image
docker compose --profile prv up -d
```

## Test the local environment

The following tests can be used to make sure all services are connected properly.

**Show running docker containers for vrun-db**
```bash
docker compose ps
```
Make sure the `vrun-db-srv` container is showing `(healthy)` in the STATUS

**Jump into the srv docker and send a command to prv**
```bash
docker exec -it vrun-db-srv sh
export ADDRESS="<your wallet address in lower case>"
echo -e "CHAINID = 560048\nADDRESS = ${ADDRESS}\nCOMMAND = pubkey" | nc -w 1 prv 5000
```

**Jump into the srv docker and trigger a refresh for act**
```bash
docker exec -it vrun-db-srv sh
echo 'rf' > $ACT_FIFO_DIR/$ACT_FIFO_FILE
```

## Additional notes

Currently, the db services only work with Lighthouse as validator backend. The Lighthouse validator should be started with at least the following flags:
```bash
--http-port 5063 --unencrypted-http-transport --http --http-address 0.0.0.0
```

You can change the http-port and http-address according to your needs.
