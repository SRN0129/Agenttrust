# Multi-stage Docker build for AgentTrust
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./
COPY client/package*.json ./client/

# Install dependencies
RUN npm ci
RUN npm --prefix client ci

# Copy full source
COPY . .

# Build client production bundle
RUN npm run build:client

# Production runtime stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4000

COPY --from=builder /app ./

EXPOSE 4000

CMD ["npx", "tsx", "server/index.ts"]
