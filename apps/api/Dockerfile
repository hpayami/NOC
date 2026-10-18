# Management-plane API. Runs as non-root, no packet-capture privileges, no host networking.
FROM node:22-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@10.28.0 --activate
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json .npmrc tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter @noc/api...
COPY packages/shared packages/shared
COPY apps/api apps/api
RUN pnpm --filter @noc/api build \
 && pnpm --filter @noc/api --prod deploy /out

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
RUN useradd --create-home --uid 10001 app
WORKDIR /srv
COPY --from=build --chown=app:app /out/node_modules ./node_modules
COPY --from=build --chown=app:app /repo/apps/api/dist ./dist
COPY --from=build --chown=app:app /repo/apps/api/drizzle ./dist/drizzle
COPY --from=build --chown=app:app /repo/apps/api/package.json ./package.json
USER app
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:4000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
