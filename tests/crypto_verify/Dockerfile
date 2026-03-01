# CryptoFS Encryption Path Verification
# Lightweight Alpine image with OpenSSL for testing the crypto primitives
FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc musl-dev openssl-dev make

WORKDIR /build
COPY crypto_verify.c Makefile ./
RUN make

FROM alpine:3.20
RUN apk add --no-cache libcrypto3
COPY --from=builder /build/crypto_verify /usr/local/bin/crypto_verify

ENTRYPOINT ["/usr/local/bin/crypto_verify"]
