FROM node:18-alpine

# Install dependencies required by dockcheck.sh
RUN apk add --no-cache \
    bash \
    curl \
    docker-cli \
    jq \
    sed \
    grep

WORKDIR /app

# Copy package files first for caching
COPY package*.json ./
RUN npm install --production

# Copy app source
COPY . .

# Environment defaults
ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "start"]
