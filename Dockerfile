FROM rust:latest as builder
WORKDIR /usr/src/notary-server
COPY . .
RUN cargo install --path .

FROM ubuntu:latest
WORKDIR /usr/src/notary-server
COPY --from=builder /usr/src/notary-server/src/config/config.yaml /usr/src/notary-server/src/config/config.yaml
COPY --from=builder /usr/src/notary-server/src/fixture /usr/src/notary-server/src/fixture
COPY --from=builder /usr/local/cargo/bin/notary-server /usr/local/bin/notary-server
ENTRYPOINT [ "notary-server" ]
