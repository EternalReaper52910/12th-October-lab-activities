# ==============================================================================
# LAB ACTIVITY 1: Remediated & Hardened Multi-Stage Dockerfile (Secure)
# Base Image: node:22-alpine (Minimal attack surface, 0 OS CVEs)
# Security Remediations Implemented:
# 1. Base Image Hardening: Upgraded to minimal alpine Linux base
# 2. Multi-stage build separating build tools from production runtime
# 3. Principle of Least Privilege: Running as unprivileged non-root user 'node'
# 4. Cleared package manager caches and eliminated build artifacts
# 5. Added dumb-init for proper signal handling (PID 1) and container lifecycle
# 6. Built-in container HEALTHCHECK instruction
# ==============================================================================

# Stage 1: Build & Dependency Resolution
FROM node:22-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Stage 2: Hardened Production Runtime
FROM node:22-alpine

# Security Patching & Process Manager Installation
RUN apk --no-cache upgrade && \
    apk add --no-cache dumb-init

WORKDIR /usr/src/app

# Enforce Non-Root Execution
USER node

# Copy dependencies and application code with non-root ownership
COPY --chown=node:node --from=builder /usr/src/app/node_modules ./node_modules
COPY --chown=node:node . .

ENV NODE_ENV=production
ENV PORT=3000
ENV SECURITY_GATE_ENABLED=true

EXPOSE 3000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]
