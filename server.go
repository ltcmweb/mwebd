package mwebd

import (
	"fmt"
	"net"
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
		for _, utxo := range utxos {
			coin, err := mweb.RewindOutput(utxo.Output, scanSecret)
			if err != nil {
				continue
			}
			chainParams := s.CS.ChainParams()
			addr := ltcutil.NewAddressMweb(coin.Address, &chainParams)
			ch <- &Utxo{
				Height:   utxo.Height,
				OutputId: utxo.OutputId.String(),
				Value:    coin.Value,
				Address:  addr.String(),
			}
		}
	}
}

func (s *Server) Utxos(req *UtxosRequest, stream Rpc_UtxosServer) (err error) {
	ch := make(chan *Utxo)
	s.mtx.Lock()
	s.utxoChan[(*mw.SecretKey)(req.ScanSecret)] = ch
	s.mtx.Unlock()

	for {
		if err = stream.Send(<-ch); err != nil {
			s.Log.Errorf("Failed to send: %v", err)
			break
		}
	}

	s.mtx.Lock()
	delete(s.utxoChan, (*mw.SecretKey)(req.ScanSecret))
	s.mtx.Unlock()
	return
}
