# nginx with ngx_bot_verifier as a dynamic module, built against the official
# image it runs in:
#
#   docker build -t nginx-bot-verifier .
#
# or use examples/docker-compose.yml.

ARG NGINX_VERSION=1.30.6
ARG HIREDIS_VERSION=1.5.0

FROM nginx:${NGINX_VERSION} AS build
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
COPY config /src/config
COPY src /src/src
RUN cd "nginx-${NGINX_VERSION}" \
    && ./configure --with-compat \
         --with-cc-opt="-I/build/hiredis/include" --with-ld-opt="-L/build/hiredis/lib" \
         --add-dynamic-module=/src \
    && make modules
COPY script/fetch-ranges /build/fetch-ranges
# Published crawler ranges as of the image build; refresh them in production.
RUN /build/fetch-ranges /build/bot_ranges

FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
COPY --from=build /build/nginx-${NGINX_VERSION}/objs/ngx_http_bot_verifier_module.so /etc/nginx/modules/
COPY --from=build /build/bot_ranges /etc/nginx/bot_ranges
RUN sed -i '1i load_module modules/ngx_http_bot_verifier_module.so;' /etc/nginx/nginx.conf
