FROM rust:1.78.0-buster

WORKDIR /usr/src/bollard

COPY . .

RUN cargo build
