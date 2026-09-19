# Production image for BruteForceGuard (Phase 9.4):
# builds the Vite dashboard and serves it with Nginx, which also proxies
# /api/* to the FastAPI backend.

# ---------------------------------------------------------------------------
# Stage 1 - build the React dashboard
# ---------------------------------------------------------------------------
FROM node:22-alpine AS frontend-build

WORKDIR /app

# Install dependencies from the lockfile first so the layer is cached.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./

# Same-origin by default: the browser calls /api/... and Nginx forwards it to
# the backend.  Override at build time to point at an absolute API origin.
ARG VITE_API_BASE_URL=
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 - serve the built dashboard and proxy the API
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine

COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=frontend-build /app/dist /usr/share/nginx/html

EXPOSE 80

# Self-contained liveness probe for the proxy (serves static /healthz).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "-", "http://127.0.0.1/healthz"]

CMD ["nginx", "-g", "daemon off;"]