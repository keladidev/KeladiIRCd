# KeladiIRCd release build. Build context: the repository root.
FROM rust:1.82-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home keladiircd
COPY --from=build /src/target/release/keladiircd /usr/local/bin/keladiircd
USER keladiircd
ENTRYPOINT ["keladiircd"]
