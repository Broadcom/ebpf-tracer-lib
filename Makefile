GOOS ?= linux
GOARCH ?= amd64

SRC_DIR := $(shell dirname $(abspath $(firstword $(MAKEFILE_LIST))))
INSTALLED_TOOLS_DIR ?= $(SRC_DIR)/bin
BPF2GO = $(INSTALLED_TOOLS_DIR)/bpf2go

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

define install-tools
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(INSTALLED_TOOLS_DIR) GOFLAGS="-mod=mod" go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

.PHONY: all
all: compile


.PHONY: prereqs
prereqs:
	@echo "Checking if bpf2go prerequisites is installed, and will install it if missing"
	$(call install-tools,$(BPF2GO),github.com/cilium/ebpf/cmd/bpf2go@v0.12.3)


.PHONY: compile
compile: export BPF_CLANG := $(CLANG)
compile: export BPF_CFLAGS := $(CFLAGS)
compile: export BPF2GO := $(BPF2GO)
compile: prereqs
	@echo "Generating BPF golang bindings"
	go generate ./cmd/...

	
