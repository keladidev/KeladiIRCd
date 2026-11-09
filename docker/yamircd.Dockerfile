# YamIRCd release build. Build context: the repository root.
FROM rust:1.82-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home yamircd
COPY --from=build /src/target/release/yamircd /usr/local/bin/yamircd
USER yamircd
ENTRYPOINT ["yamircd"]
