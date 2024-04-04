FROM node:20.10-alpine3.19

# make the 'app' folder the current working directory
WORKDIR /app

RUN apk add --no-cache openssl openssl-dev

COPY package*.json ./
COPY yarn.lock ./
RUN yarn

# copy project files and folders to the current working directory (i.e. 'app' folder)
COPY . .

RUN yarn

RUN yarn build

EXPOSE 8080
CMD [ "yarn", "serve" ]
