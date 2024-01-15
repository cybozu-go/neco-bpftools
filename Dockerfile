FROM ghcr.io/cybozu/golang:1.21-jammy AS build

COPY . /work/neco-bpftools
WORKDIR /work/neco-bpftools

RUN apt-get update -y && \
	apt-get install -y llvm clang libbpf-dev

RUN make build

FROM ghcr.io/cybozu/ubuntu:22.04
LABEL org.opencontainers.image.source="https://github.com/cybozu-go/neco-bpftools"

COPY --from=build /work/neco-bpftools/bin/* /usr/local/bin
