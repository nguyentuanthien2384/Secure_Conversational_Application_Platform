FROM rust:1.91-slim@sha256:f75071363e7f4771769d4cf81b1b7b290e607f4d4459e8731f6abdcee9982dc8 AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/source/target \
    cargo build --locked --release && cp target/release/scap-mls-native /scap-mls-native

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
COPY --from=build /scap-mls-native /usr/local/bin/scap-mls-native
USER 65534:65534
ENTRYPOINT ["scap-mls-native"]

