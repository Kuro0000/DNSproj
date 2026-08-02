FROM gcc:13 AS build
WORKDIR /src
COPY dns.h dns.c serverDNS.c Resolver.c ./
RUN gcc -Wall -Wextra -O2 serverDNS.c dns.c -o serverDNS && gcc -Wall -Wextra -O2 Resolver.c dns.c -o resolver

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils tcpdump && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/serverDNS /src/resolver /usr/local/bin/