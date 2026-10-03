# Multi-stage build: the final image contains the standalone Next.js server and
# no toolchain.
FROM node:22-alpine AS build

WORKDIR /src/apps/web

# Copy manifests first so the dependency download is cached independently of source.
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci

COPY apps/web/ ./

# `output: 'standalone'` in next.config.ts emits .next/standalone, which bundles
# the server and only the dependencies it actually loads.
RUN npx next build

FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY --from=build /src/apps/web/.next/standalone ./
# Static assets live outside the standalone folder and have to be placed next to
# the server for it to serve them.
COPY --from=build /src/apps/web/.next/static ./.next/static

# The base image's `node` user is unprivileged already; running as root in a
# container that only ever serves HTTP buys nothing.
USER node

EXPOSE 3000

ENV PORT=3000 HOSTNAME=0.0.0.0

CMD ["node", "server.js"]
