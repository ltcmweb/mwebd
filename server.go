package mwebd

import (
	context "context"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/btcsuite/btclog"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/neutrino"
	"google.golang.org/grpc"
)

type Server struct {
	UnimplementedRpcServer
	Port     int
	CS       *neutrino.ChainService
	Log      btclog.Logger
	mtx      sync.Mutex
	utxoChan map[*mw.SecretKey]chan *Utxo
}

func (s *Server) Start() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", s.Port))
	if err != nil {
		s.Log.Errorf("Failed to listen: %v", err)
		return
	}

	s.utxoChan = map[*mw.SecretKey]chan *Utxo{}
	s.CS.RegisterMwebUtxosCallback(s.utxoHandler)

	server := grpc.NewServer()
	RegisterRpcServer(server, s)
	server.Serve(lis)
}

func (s *Server) utxoHandler(lfs *mweb.Leafset, utxos []*wire.MwebNetUtxo) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for scanSecret, ch := range s.utxoChan {
		for _, utxo := range s.filterUtxos(scanSecret, utxos) {
			ch <- utxo
		}
	}
}

func (s *Server) filterUtxos(scanSecret *mw.SecretKey,
	utxos []*wire.MwebNetUtxo) (result []*Utxo) {

	for _, utxo := range utxos {
		coin, err := mweb.RewindOutput(utxo.Output, scanSecret)
		if err != nil {
			continue
		}
		chainParams := s.CS.ChainParams()
		addr := ltcutil.NewAddressMweb(coin.Address, &chainParams)
		result = append(result, &Utxo{
			Height:   utxo.Height,
			Value:    coin.Value,
			Address:  addr.String(),
			OutputId: utxo.OutputId.String(),
		})
	}
	return
}

func (s *Server) Utxos(req *UtxosRequest, stream Rpc_UtxosServer) (err error) {
	scanSecret := (*mw.SecretKey)(req.ScanSecret)
	ch := make(chan *Utxo)
	s.mtx.Lock()
	s.utxoChan[scanSecret] = ch
	s.mtx.Unlock()

	heightMap, err := s.CS.MwebCoinDB.GetLeavesAtHeight()
	if err != nil {
		return err
	}
	var heights []uint32
	for height := range heightMap {
		heights = append(heights, height)
	}
	slices.Sort(heights)
	index, _ := slices.BinarySearch(heights, uint32(req.FromHeight))
	leaf := uint64(0)
	if index > 0 {
		leaf = heightMap[heights[index-1]]
	}

	lfs, err := s.CS.MwebCoinDB.GetLeafset()
	if err != nil {
		return err
	}
	var leaves []uint64
	for ; leaf < lfs.Size; leaf++ {
		if lfs.Contains(leaf) {
			leaves = append(leaves, leaf)
		}
	}

	utxos, err := s.CS.MwebCoinDB.FetchLeaves(leaves)
	if err != nil {
		return err
	}
	for _, utxo := range s.filterUtxos(scanSecret, utxos) {
		if err = stream.Send(utxo); err != nil {
			s.Log.Errorf("Failed to send: %v", err)
			goto done
		}
	}

	for {
		if err = stream.Send(<-ch); err != nil {
			s.Log.Errorf("Failed to send: %v", err)
			break
		}
	}

done:
	s.mtx.Lock()
	delete(s.utxoChan, scanSecret)
	s.mtx.Unlock()
	return
}

func (s *Server) Addresses(ctx context.Context,
	req *AddressRequest) (*AddressResponse, error) {

	keychain := &mweb.Keychain{
		Scan:        (*mw.SecretKey)(req.ScanSecret),
		SpendPubKey: (*mw.PublicKey)(req.SpendPubkey),
	}
	resp := &AddressResponse{}
	for i := req.FromIndex; i < req.ToIndex; i++ {
		chainParams := s.CS.ChainParams()
		addr := ltcutil.NewAddressMweb(keychain.Address(i), &chainParams)
		resp.Address = append(resp.Address, addr.String())
	}
	return resp, nil
}
