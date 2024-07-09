// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeSslDoHandshake    *ebpf.ProgramSpec `ebpf:"uprobe_ssl_do_handshake"`
	UprobeSslRead           *ebpf.ProgramSpec `ebpf:"uprobe_ssl_read"`
	UprobeSslReadEx         *ebpf.ProgramSpec `ebpf:"uprobe_ssl_read_ex"`
	UprobeSslShutdown       *ebpf.ProgramSpec `ebpf:"uprobe_ssl_shutdown"`
	UprobeSslWrite          *ebpf.ProgramSpec `ebpf:"uprobe_ssl_write"`
	UprobeSslWriteEx        *ebpf.ProgramSpec `ebpf:"uprobe_ssl_write_ex"`
	UretprobeSslDoHandshake *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_do_handshake"`
	UretprobeSslRead        *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_read"`
	UretprobeSslReadEx      *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_read_ex"`
	UretprobeSslWrite       *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_write"`
	UretprobeSslWriteEx     *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_write_ex"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	ActiveAcceptArgs    *ebpf.MapSpec `ebpf:"active_accept_args"`
	ActiveConnectArgs   *ebpf.MapSpec `ebpf:"active_connect_args"`
	ActiveRdArgsMap     *ebpf.MapSpec `ebpf:"active_rd_args_map"`
	ActiveRecvArgs      *ebpf.MapSpec `ebpf:"active_recv_args"`
	ActiveSendArgs      *ebpf.MapSpec `ebpf:"active_send_args"`
	ActiveWrArgsMap     *ebpf.MapSpec `ebpf:"active_wr_args_map"`
	ConnectionTypeMap   *ebpf.MapSpec `ebpf:"connection_type_map"`
	Events              *ebpf.MapSpec `ebpf:"events"`
	FilteredConnections *ebpf.MapSpec `ebpf:"filtered_connections"`
	HttpConnMap         *ebpf.MapSpec `ebpf:"http_conn_map"`
	HttpPidMap          *ebpf.MapSpec `ebpf:"http_pid_map"`
	HttpinfoMap         *ebpf.MapSpec `ebpf:"httpinfo_map"`
	PidConnMetadata     *ebpf.MapSpec `ebpf:"pid_conn_metadata"`
	SocketDataMap       *ebpf.MapSpec `ebpf:"socket_data_map"`
	SocketInfoMap       *ebpf.MapSpec `ebpf:"socket_info_map"`
	SslConnection       *ebpf.MapSpec `ebpf:"ssl_connection"`
	SslMetadata         *ebpf.MapSpec `ebpf:"ssl_metadata"`
	SslPidMetadata      *ebpf.MapSpec `ebpf:"ssl_pid_metadata"`
	SslReadArgs         *ebpf.MapSpec `ebpf:"ssl_read_args"`
	SslWriteArgs        *ebpf.MapSpec `ebpf:"ssl_write_args"`
	WhitelistMap        *ebpf.MapSpec `ebpf:"whitelist_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	ActiveAcceptArgs    *ebpf.Map `ebpf:"active_accept_args"`
	ActiveConnectArgs   *ebpf.Map `ebpf:"active_connect_args"`
	ActiveRdArgsMap     *ebpf.Map `ebpf:"active_rd_args_map"`
	ActiveRecvArgs      *ebpf.Map `ebpf:"active_recv_args"`
	ActiveSendArgs      *ebpf.Map `ebpf:"active_send_args"`
	ActiveWrArgsMap     *ebpf.Map `ebpf:"active_wr_args_map"`
	ConnectionTypeMap   *ebpf.Map `ebpf:"connection_type_map"`
	Events              *ebpf.Map `ebpf:"events"`
	FilteredConnections *ebpf.Map `ebpf:"filtered_connections"`
	HttpConnMap         *ebpf.Map `ebpf:"http_conn_map"`
	HttpPidMap          *ebpf.Map `ebpf:"http_pid_map"`
	HttpinfoMap         *ebpf.Map `ebpf:"httpinfo_map"`
	PidConnMetadata     *ebpf.Map `ebpf:"pid_conn_metadata"`
	SocketDataMap       *ebpf.Map `ebpf:"socket_data_map"`
	SocketInfoMap       *ebpf.Map `ebpf:"socket_info_map"`
	SslConnection       *ebpf.Map `ebpf:"ssl_connection"`
	SslMetadata         *ebpf.Map `ebpf:"ssl_metadata"`
	SslPidMetadata      *ebpf.Map `ebpf:"ssl_pid_metadata"`
	SslReadArgs         *ebpf.Map `ebpf:"ssl_read_args"`
	SslWriteArgs        *ebpf.Map `ebpf:"ssl_write_args"`
	WhitelistMap        *ebpf.Map `ebpf:"whitelist_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ActiveAcceptArgs,
		m.ActiveConnectArgs,
		m.ActiveRdArgsMap,
		m.ActiveRecvArgs,
		m.ActiveSendArgs,
		m.ActiveWrArgsMap,
		m.ConnectionTypeMap,
		m.Events,
		m.FilteredConnections,
		m.HttpConnMap,
		m.HttpPidMap,
		m.HttpinfoMap,
		m.PidConnMetadata,
		m.SocketDataMap,
		m.SocketInfoMap,
		m.SslConnection,
		m.SslMetadata,
		m.SslPidMetadata,
		m.SslReadArgs,
		m.SslWriteArgs,
		m.WhitelistMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeSslDoHandshake    *ebpf.Program `ebpf:"uprobe_ssl_do_handshake"`
	UprobeSslRead           *ebpf.Program `ebpf:"uprobe_ssl_read"`
	UprobeSslReadEx         *ebpf.Program `ebpf:"uprobe_ssl_read_ex"`
	UprobeSslShutdown       *ebpf.Program `ebpf:"uprobe_ssl_shutdown"`
	UprobeSslWrite          *ebpf.Program `ebpf:"uprobe_ssl_write"`
	UprobeSslWriteEx        *ebpf.Program `ebpf:"uprobe_ssl_write_ex"`
	UretprobeSslDoHandshake *ebpf.Program `ebpf:"uretprobe_ssl_do_handshake"`
	UretprobeSslRead        *ebpf.Program `ebpf:"uretprobe_ssl_read"`
	UretprobeSslReadEx      *ebpf.Program `ebpf:"uretprobe_ssl_read_ex"`
	UretprobeSslWrite       *ebpf.Program `ebpf:"uretprobe_ssl_write"`
	UretprobeSslWriteEx     *ebpf.Program `ebpf:"uretprobe_ssl_write_ex"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeSslDoHandshake,
		p.UprobeSslRead,
		p.UprobeSslReadEx,
		p.UprobeSslShutdown,
		p.UprobeSslWrite,
		p.UprobeSslWriteEx,
		p.UretprobeSslDoHandshake,
		p.UretprobeSslRead,
		p.UretprobeSslReadEx,
		p.UretprobeSslWrite,
		p.UretprobeSslWriteEx,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte
