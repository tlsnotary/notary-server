FROM rust:bookworm as builder
WORKDIR /usr/src/notary-server
COPY . .
RUN mkdir .cargo
RUN echo "[net]\ngit-fetch-with-cli  = true\n" > .cargo/config.toml
RUN cargo install --path .
CMD [ "notary-server" ]
