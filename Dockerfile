FROM docker.1ms.run/rust:alpine3.22 AS builder
WORKDIR /app
# 只拷贝构建必需的内容：不要 COPY .，否则本地 config.yaml 会进镜像层
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN apk add --no-cache pkgconfig openssl-dev openssl-libs-static gcc musl-dev
RUN export OPENSSL_STATIC="1" && cargo build --release

FROM docker.1ms.run/alpine:latest
WORKDIR /app
COPY --from=builder /app/target/release/p-proxy /app/p-proxy
COPY config.example.yaml /app/config.example.yaml
# 运行时把真实配置挂载为 /app/config.yaml
CMD ["./p-proxy"]
