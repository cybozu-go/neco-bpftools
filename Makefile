BPFTOOL := /usr/local/bin/bpftool

.PHONY: build
build: bpftool
	$(MAKE) -C socket-tracer build

.PHONY: bpftool
bpftool: $(BPFTOOL)
$(BPFTOOL):
	git clone --recurse-submodules https://github.com/libbpf/bpftool.git
	cd bpftool && \
	git submodule update --init && \
	cd src && \
	$(MAKE) && \
	$(SUDO) $(MAKE) install
