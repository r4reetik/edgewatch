# syntax=docker/dockerfile:1

# Keelson ships only as this image. It is kept small: the final stage is Alpine with
# the Node.js binary and the C++ runtime it needs, and nothing else from Node's image
# (no npm, Yarn or Corepack, which also keeps their dependencies out of image scans).

# The build runs on the build machine's own platform, even for the arm64 image: its
# output is plain JavaScript, and so are the runtime dependencies (test/env.test.ts
# checks), so nothing here has to run under emulation.
FROM --platform=$BUILDPLATFORM node:26-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY web ./web
RUN npm run build \
 && npm prune --omit=dev --no-audit --no-fund \
 && find node_modules \( -name '*.d.ts' -o -name '*.d.mts' -o -name '*.d.cts' -o -name '*.map' -o -name '*.md' \) -delete \
 && find node_modules -type d -empty -delete \
 && rm -f node_modules/.package-lock.json

# Node.js for the target platform. Keep its Alpine version the same as the stage below,
# so the binary and the libstdc++ installed there come from the same release.
FROM node:26-alpine3.24 AS node

FROM alpine:3.24
LABEL org.opencontainers.image.source="https://github.com/r4reetik/keelson" \
      org.opencontainers.image.description="Security posture tracking for Cloudflare, Vercel and AWS. Read-only." \
      org.opencontainers.image.licenses="MIT"
# The node user has uid 1000, as in Node's own images, so /data volumes made with
# earlier Keelson images stay readable.
RUN apk add --no-cache libstdc++ \
 && addgroup -g 1000 node \
 && adduser -u 1000 -G node -s /bin/sh -D node \
 && mkdir -p /data && chown node:node /data && chmod 700 /data
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# Only the install marker: in the image, Keelson defaults to 0.0.0.0 and /data itself (src/env.ts).
ENV NODE_ENV=production \
    KEELSON_INSTALL=docker
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
VOLUME ["/data"]
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.KEELSON_PORT || process.env.PORT || 4317) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "dist/bin.js", "--no-open"]
