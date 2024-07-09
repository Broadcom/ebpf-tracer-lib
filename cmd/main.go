package main

import (
	"log"
)

//go:generate ../bin/bpf2go -no-global-types -output-dir ../target/openssl -target amd64 bpf ../pkg/broadcom/bpf/probes/openssl.c -- -I../pkg/broadcom/bpf/probes/headers
//go:generate ../bin/bpf2go -no-global-types -output-dir ../target/protocol -target amd64 bpf ../pkg/broadcom/bpf/probes/protocol_tracing.c -- -I../pkg/broadcom/bpf/probes/headers

func main() {

	log.Printf("Sample go file")

}
