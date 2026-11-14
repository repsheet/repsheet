# Images for trying Repsheet:
#
#   docker build --target valkey -t repsheet-valkey .
#   docker build --target nginx  -t repsheet-nginx  .
#
# or use examples/docker-compose.yml. Modules are built inside the official
# images they run in, so they match that nginx and Valkey exactly.

ARG NGINX_VERSION=1.30.6
ARG VALKEY_VERSION=9.1.3
ARG HIREDIS_VERSION=1.5.0

# --------------------------------------------------------------------------
FROM valkey/valkey:${VALKEY_VERSION} AS valkey-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY common /src/common
COPY redis /src/redis
RUN make -C /src/redis clean all

FROM valkey/valkey:${VALKEY_VERSION} AS valkey
COPY --from=valkey-build /src/redis/repsheet.so /usr/local/lib/repsheet.so
CMD ["valkey-server", "--loadmodule", "/usr/local/lib/repsheet.so"]

# --------------------------------------------------------------------------
FROM nginx:${NGINX_VERSION} AS nginx-build
ARG NGINX_VERSION
ARG HIREDIS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# hiredis is linked statically so the runtime image needs no extra packages.
RUN curl -fsSL "https://github.com/redis/hiredis/archive/refs/tags/v${HIREDIS_VERSION}.tar.gz" | tar xz \
    && make -C "hiredis-${HIREDIS_VERSION}" CFLAGS="-fPIC -O2" USE_SSL=0 PREFIX=/build/hiredis install \
    && rm -f /build/hiredis/lib/*.so*
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar xz
COPY common /src/common
COPY nginx /src/nginx
RUN cd "nginx-${NGINX_VERSION}" \
    && ./configure --with-compat \
         --with-cc-opt="-I/build/hiredis/include" --with-ld-opt="-L/build/hiredis/lib" \
         --add-dynamic-module=/src/nginx \
    && make modules

FROM nginx:${NGINX_VERSION} AS nginx
ARG NGINX_VERSION
COPY --from=nginx-build /build/nginx-${NGINX_VERSION}/objs/ngx_http_repsheet_module.so /etc/nginx/modules/
RUN sed -i '1i load_module modules/ngx_http_repsheet_module.so;' /etc/nginx/nginx.conf
