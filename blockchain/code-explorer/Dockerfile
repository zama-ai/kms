FROM node:20.10-alpine3.19

# make the 'app' folder the current working directory
WORKDIR /app

RUN apk add --no-cache openssl openssl-dev python3 py3-pip build-base

COPY package*.json ./
COPY yarn.lock ./
RUN yarn

# copy project files and folders to the current working directory (i.e. 'app' folder)
COPY . .

RUN yarn install

ENV NODE_OPTIONS=--openssl-legacy-provider

EXPOSE 3000
CMD [ "yarn", "start-devnet" ]
