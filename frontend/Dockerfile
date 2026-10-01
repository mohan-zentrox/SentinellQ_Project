FROM node:20-alpine AS build
WORKDIR /app

# Vite inlines VITE_* vars at BUILD time, so the API base URL has to be a
# build arg -- passing it as a runtime container env (as an earlier version of
# docker-compose.yml did) has no effect on an already-compiled bundle.
# Default is the same-origin path that nginx.conf proxies to the backend.
ARG VITE_API_BASE_URL=/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 CMD wget -qO- http://127.0.0.1:80/ >/dev/null 2>&1 || exit 1
CMD ["nginx", "-g", "daemon off;"]
