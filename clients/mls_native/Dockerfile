FROM rust:1.91-slim AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:trixie-slim
COPY --from=build /source/target/release/scap-mls-native /usr/local/bin/scap-mls-native
USER 65534:65534
ENTRYPOINT ["scap-mls-native"]

