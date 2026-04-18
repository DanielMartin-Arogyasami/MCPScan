FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json tsup.config.* ./
COPY src/ src/

RUN npm run build

# --- production stage ---
FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force

COPY --from=builder /app/dist/ dist/

RUN mkdir -p /target

USER node

ENTRYPOINT ["node", "/app/dist/cli.js"]
