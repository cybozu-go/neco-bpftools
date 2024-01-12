PROJECT := socket-tracer

BIN_DIR := ../bin
HEADER_DIR := ./bpf/include
VMLINUX := $(HEADER_DIR)/vmlinux.h

.PHONY: build
build: vmlinux
	go generate ./...
	CGO_ENABLED=0 go build -o  -ldflags="-w -s" -o $(BIN_DIR)/$(PROJECT)

.PHONY: clean
clean:
	rm $(BIN_DIR)/$(PROJECT)
	go clean


.PHONY: vmlinux
vmlinux: $(VMLINUX)
$(VMLINUX):
	mkdir -p $(HEADER_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
