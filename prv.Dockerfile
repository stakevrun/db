# Create binary package using node
FROM node:23-alpine3.20 AS build

WORKDIR /usr/app

COPY . .

RUN npm install && \
    npx esbuild prv.js --bundle --outfile=build.cjs --format=cjs --platform=node && \
    npx pkg --targets latest-alpine-x64  build.cjs

# Create clean docker with just the needed binary and git
FROM alpine:3.20

ARG HOME_DIR=/usr/share/db
ARG PRV_USER=db-prv
ARG STATE_DIR=/mnt/crypt/db

WORKDIR ${HOME_DIR}

COPY --from=build /usr/app/build prv

RUN apk add git && \
    addgroup -S ${PRV_USER} && \
    adduser -S ${PRV_USER} -G ${PRV_USER} -h ${HOME_DIR} && \
    mkdir -p ${STATE_DIR} && \
    chown -R ${PRV_USER}:${PRV_USER} ${HOME_DIR} ${STATE_DIR}

VOLUME ${STATE_DIR}

USER ${PRV_USER}

ENTRYPOINT ["./prv"]
