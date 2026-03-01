# CryptoFS Encryption Demo
FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc musl-dev openssl-dev make

WORKDIR /build
COPY cryptofs_demo.c Makefile ./
RUN make

FROM alpine:3.20
RUN apk add --no-cache libcrypto3
COPY --from=builder /build/cryptofs_demo /usr/local/bin/cryptofs_demo

# The volumes /data/encrypted and /data/plaintext are mounted from the host
VOLUME ["/data/encrypted", "/data/plaintext"]

ENTRYPOINT ["/usr/local/bin/cryptofs_demo"]
