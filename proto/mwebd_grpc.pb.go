// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v5.27.1
// source: mwebd.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	Rpc_Status_FullMethodName         = "/Rpc/Status"
	Rpc_Utxos_FullMethodName          = "/Rpc/Utxos"
	Rpc_Addresses_FullMethodName      = "/Rpc/Addresses"
	Rpc_LedgerKeys_FullMethodName     = "/Rpc/LedgerKeys"
	Rpc_Spent_FullMethodName          = "/Rpc/Spent"
	Rpc_Create_FullMethodName         = "/Rpc/Create"
	Rpc_LedgerExchange_FullMethodName = "/Rpc/LedgerExchange"
	Rpc_Broadcast_FullMethodName      = "/Rpc/Broadcast"
)

// RpcClient is the client API for Rpc service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RpcClient interface {
	// Get the sync status of the daemon. The block headers are
	// synced first, followed by a subset of MWEB headers, and
	// finally the MWEB utxo set.
	Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	// Get a continuous stream of unspent MWEB outputs (utxos)
	// for an account.
	Utxos(ctx context.Context, in *UtxosRequest, opts ...grpc.CallOption) (Rpc_UtxosClient, error)
	// Get a batch of MWEB addresses for an account.
	Addresses(ctx context.Context, in *AddressRequest, opts ...grpc.CallOption) (*AddressResponse, error)
	// Get the scan secret and spend pubkey from a Ledger
	// for a given HD path.
	LedgerKeys(ctx context.Context, in *LedgerKeysRequest, opts ...grpc.CallOption) (*LedgerKeysResponse, error)
	// Check whether MWEB outputs are in the unspent set or not.
	// This is used to determine when outputs have been spent by
	// either this or another wallet using the same seed, and to
	// determine when MWEB transactions have confirmed by checking
	// the output IDs of the MWEB inputs and outputs.
	Spent(ctx context.Context, in *SpentRequest, opts ...grpc.CallOption) (*SpentResponse, error)
	// Create the MWEB portion of a transaction.
	Create(ctx context.Context, in *CreateRequest, opts ...grpc.CallOption) (*CreateResponse, error)
	// Process APDUs from the Ledger.
	LedgerExchange(ctx context.Context, in *LedgerApdu, opts ...grpc.CallOption) (*LedgerApdu, error)
	// Broadcast a transaction to the network. This is provided as
	// existing broadcast services may not support MWEB transactions.
	Broadcast(ctx context.Context, in *BroadcastRequest, opts ...grpc.CallOption) (*BroadcastResponse, error)
}

type rpcClient struct {
	cc grpc.ClientConnInterface
}

func NewRpcClient(cc grpc.ClientConnInterface) RpcClient {
	return &rpcClient{cc}
}

func (c *rpcClient) Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StatusResponse)
	err := c.cc.Invoke(ctx, Rpc_Status_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Utxos(ctx context.Context, in *UtxosRequest, opts ...grpc.CallOption) (Rpc_UtxosClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Rpc_ServiceDesc.Streams[0], Rpc_Utxos_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &rpcUtxosClient{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Rpc_UtxosClient interface {
	Recv() (*Utxo, error)
	grpc.ClientStream
}

type rpcUtxosClient struct {
	grpc.ClientStream
}

func (x *rpcUtxosClient) Recv() (*Utxo, error) {
	m := new(Utxo)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *rpcClient) Addresses(ctx context.Context, in *AddressRequest, opts ...grpc.CallOption) (*AddressResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AddressResponse)
	err := c.cc.Invoke(ctx, Rpc_Addresses_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) LedgerKeys(ctx context.Context, in *LedgerKeysRequest, opts ...grpc.CallOption) (*LedgerKeysResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(LedgerKeysResponse)
	err := c.cc.Invoke(ctx, Rpc_LedgerKeys_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Spent(ctx context.Context, in *SpentRequest, opts ...grpc.CallOption) (*SpentResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SpentResponse)
	err := c.cc.Invoke(ctx, Rpc_Spent_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Create(ctx context.Context, in *CreateRequest, opts ...grpc.CallOption) (*CreateResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateResponse)
	err := c.cc.Invoke(ctx, Rpc_Create_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) LedgerExchange(ctx context.Context, in *LedgerApdu, opts ...grpc.CallOption) (*LedgerApdu, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(LedgerApdu)
	err := c.cc.Invoke(ctx, Rpc_LedgerExchange_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Broadcast(ctx context.Context, in *BroadcastRequest, opts ...grpc.CallOption) (*BroadcastResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BroadcastResponse)
	err := c.cc.Invoke(ctx, Rpc_Broadcast_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RpcServer is the server API for Rpc service.
// All implementations must embed UnimplementedRpcServer
// for forward compatibility
type RpcServer interface {
	// Get the sync status of the daemon. The block headers are
	// synced first, followed by a subset of MWEB headers, and
	// finally the MWEB utxo set.
	Status(context.Context, *StatusRequest) (*StatusResponse, error)
	// Get a continuous stream of unspent MWEB outputs (utxos)
	// for an account.
	Utxos(*UtxosRequest, Rpc_UtxosServer) error
	// Get a batch of MWEB addresses for an account.
	Addresses(context.Context, *AddressRequest) (*AddressResponse, error)
	// Get the scan secret and spend pubkey from a Ledger
	// for a given HD path.
	LedgerKeys(context.Context, *LedgerKeysRequest) (*LedgerKeysResponse, error)
	// Check whether MWEB outputs are in the unspent set or not.
	// This is used to determine when outputs have been spent by
	// either this or another wallet using the same seed, and to
	// determine when MWEB transactions have confirmed by checking
	// the output IDs of the MWEB inputs and outputs.
	Spent(context.Context, *SpentRequest) (*SpentResponse, error)
	// Create the MWEB portion of a transaction.
	Create(context.Context, *CreateRequest) (*CreateResponse, error)
	// Process APDUs from the Ledger.
	LedgerExchange(context.Context, *LedgerApdu) (*LedgerApdu, error)
	// Broadcast a transaction to the network. This is provided as
	// existing broadcast services may not support MWEB transactions.
	Broadcast(context.Context, *BroadcastRequest) (*BroadcastResponse, error)
	mustEmbedUnimplementedRpcServer()
}

// UnimplementedRpcServer must be embedded to have forward compatible implementations.
type UnimplementedRpcServer struct {
}

func (UnimplementedRpcServer) Status(context.Context, *StatusRequest) (*StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Status not implemented")
}
func (UnimplementedRpcServer) Utxos(*UtxosRequest, Rpc_UtxosServer) error {
	return status.Errorf(codes.Unimplemented, "method Utxos not implemented")
}
func (UnimplementedRpcServer) Addresses(context.Context, *AddressRequest) (*AddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Addresses not implemented")
}
func (UnimplementedRpcServer) LedgerKeys(context.Context, *LedgerKeysRequest) (*LedgerKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LedgerKeys not implemented")
}
func (UnimplementedRpcServer) Spent(context.Context, *SpentRequest) (*SpentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Spent not implemented")
}
func (UnimplementedRpcServer) Create(context.Context, *CreateRequest) (*CreateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedRpcServer) LedgerExchange(context.Context, *LedgerApdu) (*LedgerApdu, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LedgerExchange not implemented")
}
func (UnimplementedRpcServer) Broadcast(context.Context, *BroadcastRequest) (*BroadcastResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Broadcast not implemented")
}
func (UnimplementedRpcServer) mustEmbedUnimplementedRpcServer() {}

// UnsafeRpcServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RpcServer will
// result in compilation errors.
type UnsafeRpcServer interface {
	mustEmbedUnimplementedRpcServer()
}

func RegisterRpcServer(s grpc.ServiceRegistrar, srv RpcServer) {
	s.RegisterService(&Rpc_ServiceDesc, srv)
}

func _Rpc_Status_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).Status(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_Status_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).Status(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_Utxos_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(UtxosRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RpcServer).Utxos(m, &rpcUtxosServer{ServerStream: stream})
}

type Rpc_UtxosServer interface {
	Send(*Utxo) error
	grpc.ServerStream
}

type rpcUtxosServer struct {
	grpc.ServerStream
}

func (x *rpcUtxosServer) Send(m *Utxo) error {
	return x.ServerStream.SendMsg(m)
}

func _Rpc_Addresses_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).Addresses(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_Addresses_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).Addresses(ctx, req.(*AddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_LedgerKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LedgerKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).LedgerKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_LedgerKeys_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).LedgerKeys(ctx, req.(*LedgerKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_Spent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SpentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).Spent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_Spent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).Spent(ctx, req.(*SpentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_Create_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).Create(ctx, req.(*CreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_LedgerExchange_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LedgerApdu)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).LedgerExchange(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_LedgerExchange_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).LedgerExchange(ctx, req.(*LedgerApdu))
	}
	return interceptor(ctx, in, info, handler)
}

func _Rpc_Broadcast_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BroadcastRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RpcServer).Broadcast(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Rpc_Broadcast_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RpcServer).Broadcast(ctx, req.(*BroadcastRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Rpc_ServiceDesc is the grpc.ServiceDesc for Rpc service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Rpc_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "Rpc",
	HandlerType: (*RpcServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Status",
			Handler:    _Rpc_Status_Handler,
		},
		{
			MethodName: "Addresses",
			Handler:    _Rpc_Addresses_Handler,
		},
		{
			MethodName: "LedgerKeys",
			Handler:    _Rpc_LedgerKeys_Handler,
		},
		{
			MethodName: "Spent",
			Handler:    _Rpc_Spent_Handler,
		},
		{
			MethodName: "Create",
			Handler:    _Rpc_Create_Handler,
		},
		{
			MethodName: "LedgerExchange",
			Handler:    _Rpc_LedgerExchange_Handler,
		},
		{
			MethodName: "Broadcast",
			Handler:    _Rpc_Broadcast_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Utxos",
			Handler:       _Rpc_Utxos_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "mwebd.proto",
}
