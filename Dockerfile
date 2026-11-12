# syntax=docker/dockerfile:1

FROM node:26-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY web ./web
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM node:26-slim
LABEL org.opencontainers.image.source="https://github.com/r4reetik/keelson" \
      org.opencontainers.image.description="Security posture tracking for Cloudflare, Vercel and AWS. Read-only." \
      org.opencontainers.image.licenses="MIT"
# Only the install marker: in the image, Keelson defaults to 0.0.0.0 and /data itself
# (src/names.ts), so a KEELSON_* or an older EDGEWATCH_* variable set on the container wins.
ENV NODE_ENV=production \
    KEELSON_INSTALL=docker
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /data && chown node:node /data && chmod 700 /data
USER node
VOLUME ["/data"]
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.KEELSON_PORT || process.env.EDGEWATCH_PORT || 4317) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "dist/bin.js", "--no-open"]
