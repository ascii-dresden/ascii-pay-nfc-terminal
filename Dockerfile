FROM rust:alpine as build

RUN apk update && apk add musl-dev pkgconf pcsc-lite-dev libevdev-dev

WORKDIR /usr/src/ascii-pay-terminal
ENV CARGO_TERM_COLOR always

RUN echo "fn main() {}" > dummy.rs
COPY Cargo.toml .
COPY Cargo.lock .
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml
COPY . .
RUN cargo build --release

FROM alpine:3.16 as dist

RUN apk update && apk add pcsc-lite-libs libevdev libc6-compat

WORKDIR /opt/ascii-pay-terminal
ENTRYPOINT /opt/ascii-pay-terminal/ascii-pay-terminal

COPY --from=build /usr/src/ascii-pay-terminal/target/release/ascii-pay-terminal /opt/ascii-pay-terminal/
