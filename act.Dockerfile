# Create binary package using node
FROM node:23-alpine3.20 AS build

WORKDIR /usr/app

COPY . .

RUN npm install && \
    npx esbuild act.js --bundle --outfile=build.cjs --format=cjs --platform=node && \
    npx pkg --targets latest-alpine-x64  build.cjs

# Create clean docker with just the needed binary and git
FROM alpine:3.20

ARG HOME_DIR=/usr/share/db
ARG ACT_FIFO_DIR=/run/act
ARG ACT_USER=db-act

WORKDIR ${HOME_DIR}

COPY --from=build /usr/app/build act
COPY ./scripts/docker-entrypoint.sh.act /usr/local/bin/docker-entrypoint.sh

RUN apk add git inotify-tools && \
    addgroup -S ${ACT_USER} && \
    adduser -S ${ACT_USER} -G ${ACT_USER} -h ${HOME_DIR} && \
    mkdir -p ${ACT_FIFO_DIR} && \
    chown -R ${ACT_USER}:${ACT_USER} ${HOME_DIR} ${ACT_FIFO_DIR}

VOLUME ${ACT_FIFO_DIR}

USER ${ACT_USER}

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
