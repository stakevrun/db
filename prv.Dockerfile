# Create binary package using node
FROM node:23-alpine3.20 AS build

WORKDIR /usr/app

COPY . .

RUN npm install esbuild postject && \
    npx esbuild prv.js --bundle --format=cjs --platform=node --outfile=build.cjs && \
    echo '{ "main": "build.cjs", "output": "build.blob", "disableExperimentalSEAWarning": true }' > sea-config.json && \
    node --experimental-sea-config sea-config.json && \
    cp $(command -v node) server && \
    npx postject server NODE_SEA_BLOB build.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2

# Create clean docker with just the needed binary and git
FROM alpine:3.20

ARG HOME_DIR=/usr/share/db
ARG USER=db-prv
ARG STATE_DIR=/mnt/crypt/db

WORKDIR ${HOME_DIR}

COPY --from=build /usr/app/server server
# Copy just the two libs needed for node to run from our base image.
# If we install the full packages, our docker image will double in size and we really only need these 2 files.
COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so.6
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1

RUN apk add -U --no-cache git && \
    addgroup -S ${USER} && \
    adduser -S ${USER} -G ${USER} -h ${HOME_DIR} && \
    mkdir -p ${STATE_DIR} && \
    chown -R ${USER}:${USER} ${HOME_DIR} ${STATE_DIR}

VOLUME ${STATE_DIR}

USER ${USER}

ENTRYPOINT ["./server"]
