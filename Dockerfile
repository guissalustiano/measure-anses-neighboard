FROM docker.io/rust:1.78.0-alpine3.19 AS builder
WORKDIR /builder

RUN apk add musl-dev

COPY . .
RUN cargo build -p tracer --release --locked

FROM docker.io/alpine:3.19
WORKDIR /app

COPY --from=builder /builder/target/release/tracer ./tracer

CMD exec ./tracer
