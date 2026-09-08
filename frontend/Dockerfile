FROM node:22-alpine AS base

FROM base AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM base AS builder
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
# Product edition (ADR-0009): "full" (default) or "network_defense".
# NEXT_PUBLIC_* vars are inlined at build time by Next.js, so this MUST
# be set before `npm run build`, not just at container runtime — one
# Dockerfile, parameterized, not a second Dockerfile. Override with
# `--build-arg PRODUCT_EDITION=network_defense`.
ARG PRODUCT_EDITION=full
ENV NEXT_PUBLIC_PRODUCT_EDITION=${PRODUCT_EDITION}
RUN npm run build

FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
