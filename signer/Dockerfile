# Development image. A TEE deployment bakes the binary into the measured,
# dm-verity protected guest image instead (see ../ROADMAP.md).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/tee-signer /usr/local/bin/tee-signer
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/tee-signer"]
CMD ["serve"]
