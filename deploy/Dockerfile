# The blind-store reference server, built from this repository (DESIGN.md
# §5.3). Runs as the image's unprivileged `node` user; the Compose files add
# a read-only file system, no capabilities and a memory limit.
FROM node:24-alpine

WORKDIR /app
# The workspace manifests first, so the dependency layer is cached: the root
# lockfile pins ws and pg exactly; the other packages are workspace links the
# production install never follows.
COPY package.json package-lock.json ./
COPY packages/crypto-core/package.json packages/crypto-core/
COPY packages/identity/package.json packages/identity/
COPY packages/access/package.json packages/access/
COPY packages/mailbox/package.json packages/mailbox/
COPY packages/blind-store/package.json packages/blind-store/
COPY packages/mcp/package.json packages/mcp/
RUN npm ci --omit=dev --workspace=@microtoll/blind-store --ignore-scripts --no-audit --no-fund \
    && npm cache clean --force

COPY packages/blind-store packages/blind-store

USER node
EXPOSE 8020
ENV BLIND_STORE_PORT=8020
CMD ["node", "packages/blind-store/bin/blind-store.mjs"]
