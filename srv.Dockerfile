# Create binary package using node
FROM node:23-alpine3.20 AS build

WORKDIR /usr/app

COPY . .

RUN npm install && \
    npx esbuild srv.js --bundle --outfile=build.cjs --format=cjs --platform=node && \
    npx pkg --targets latest-alpine-x64  build.cjs

# Create clean docker with just the needed binary and git
FROM alpine:3.20

ARG HOME_DIR=/usr/share/db
ARG SRV_USER=db-srv
ARG STATE_DIR=/mnt/crypt/db

WORKDIR ${HOME_DIR}

COPY --from=build /usr/app/build srv

RUN apk add git && \
    addgroup -S ${SRV_USER} && \
    adduser -S ${SRV_USER} -G ${SRV_USER} -h ${HOME_DIR} && \
    mkdir -p ${STATE_DIR} && \
    chown -R ${SRV_USER}:${SRV_USER} ${HOME_DIR} ${STATE_DIR}

VOLUME ${STATE_DIR}

USER ${SRV_USER}

ENTRYPOINT ["./srv"]
