# Anope IRC Services built from the official source release, for testing YamIRCd.
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG ANOPE_TAG=2.1.27
RUN git clone --depth 1 --branch "$ANOPE_TAG" https://github.com/anope/anope.git /src \
 && cmake -S /src -B /src/build -DINSTDIR=/anope -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /src/build -j 8 \
 && cmake --install /src/build

FROM debian:bookworm-slim
RUN useradd --create-home anope
COPY --from=build /anope /anope
RUN chown -R anope /anope
USER anope
WORKDIR /anope
ENTRYPOINT ["/anope/bin/anope", "--nofork", "--nopid"]
