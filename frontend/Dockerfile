FROM node:24.11.1-bookworm-slim AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci

COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src
ARG VITE_API_BASE_URL=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.28.0-alpine

COPY --chown=101:101 docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /build/dist /usr/share/nginx/html

USER 101:101
EXPOSE 8080 8443

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/healthz"]
