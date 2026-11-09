# Anope IRC Services built from the official source release, for testing KeladiIRCd.
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG ANOPE_TAG=2.1.27
RUN git clone --depth 1 --branch "$ANOPE_TAG" https://github.com/anope/anope.git /src \
 && cmake -S /src -B /src/build -DINSTDIR=/anope -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /src/build -j 8 \
 && cmake --install /src/build

FROM debian:bookworm-slim AS anope
RUN useradd --create-home anope
COPY --from=build /anope /anope
RUN chown -R anope /anope
USER anope
WORKDIR /anope
ENTRYPOINT ["/anope/bin/anope", "--nofork", "--nopid"]

# The docker/ network: Anope configured at build time, secrets filled in at start.
FROM python:3.12-slim AS network-config
COPY --from=build /anope/conf /examples
COPY prepare.py /prepare.py
ARG UPLINK=172.30.0.10
ARG SERVICES_NAME=services.irc.test
RUN python -I /prepare.py /out --source /examples --uplink "$UPLINK" --name "$SERVICES_NAME" \
    --root "" --password @SERVICES_SECRET@ --rpc-token @RPC_TOKEN@

FROM anope AS network
COPY --from=network-config --chown=anope /out/ /anope/conf/
COPY --chown=anope network-entrypoint.sh /anope/bin/network-entrypoint.sh
ENTRYPOINT ["sh", "/anope/bin/network-entrypoint.sh"]

# The default target stays the plain test image.
FROM anope
