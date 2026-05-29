# syntax=docker/dockerfile:1.7
# Multi-stage build for @ultralab/misp-mcp-server
# Optimized for Glama hosting + general MCP client use.

FROM node:20-alpine AS builder

WORKDIR /app

# Install deps with full dev set for TypeScript build
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---

FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Production deps only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY --from=builder /app/dist ./dist

# MCP servers communicate via stdio; no port exposed.
# Glama's introspection probes via stdin/stdout MCP handshake.
ENTRYPOINT ["node", "dist/index.js"]
