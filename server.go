package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/btcsuite/btclog"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/neutrino"
	"github.com/ltcsuite/neutrino/mwebdb"
	"google.golang.org/grpc"
)

type Server struct {
	UnimplementedRpcServer
	Port     int
	CS       *neutrino.ChainService
	Log      btclog.Logger
	mtx      sync.Mutex
	utxoChan map[*mw.SecretKey][]chan *Utxo
}

func (s *Server) Start() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", s.Port))
	if err != nil {
		s.Log.Errorf("Failed to listen: %v", err)
		return
	}

	s.utxoChan = map[*mw.SecretKey][]chan *Utxo{}
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
			select {
			case ch[0] <- utxo:
			case <-ch[1]:
			}
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
			OutputId: hex.EncodeToString(utxo.OutputId[:]),
		})
	}
	return
}

func (s *Server) Utxos(req *UtxosRequest, stream Rpc_UtxosServer) (err error) {
	scanSecret := (*mw.SecretKey)(req.ScanSecret)
	ch, quit := make(chan *Utxo), make(chan *Utxo)
	s.mtx.Lock()
	s.utxoChan[scanSecret] = []chan *Utxo{ch, quit}
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
	close(quit)
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

func (s *Server) Spent(ctx context.Context,
	req *SpentRequest) (*SpentResponse, error) {

	resp := &SpentResponse{}
	for _, outputIdStr := range req.OutputId {
		outputId, err := hex.DecodeString(outputIdStr)
		if err != nil {
			return nil, err
		}
		if !s.CS.MwebUtxoExists((*chainhash.Hash)(outputId)) {
			resp.OutputId = append(resp.OutputId, outputIdStr)
		}
	}
	return resp, nil
}

func (s *Server) Create(ctx context.Context,
	req *CreateRequest) (*CreateResponse, error) {

	var (
		tx         wire.MsgTx
		txIns      []*wire.TxIn
		pegouts    []*wire.TxOut
		coins      []*mweb.Coin
		recipients []*mweb.Recipient
		pegin      uint64
		sumCoins   uint64
		sumOutputs uint64
	)

	err := tx.Deserialize(bytes.NewReader(req.RawTx))
	if err != nil {
		return nil, err
	}

	for _, txIn := range tx.TxIn {
		output, err := s.CS.MwebCoinDB.FetchCoin(&txIn.PreviousOutPoint.Hash)
		switch err {
		case nil:
			coin, err := mweb.RewindOutput(output, (*mw.SecretKey)(req.ScanSecret))
			if err != nil {
				return nil, err
			}

			coin.CalculateOutputKey((*mw.SecretKey)(req.SpendSecret))
			coins = append(coins, coin)
			sumCoins += coin.Value

		case mwebdb.ErrCoinNotFound:
			txIns = append(txIns, txIn)

		default:
			return nil, err
		}
	}

	for _, txOut := range tx.TxOut {
		sumOutputs += uint64(txOut.Value)
		if !txscript.IsMweb(txOut.PkScript) {
			pegouts = append(pegouts, txOut)
			continue
		}

		chainParams := s.CS.ChainParams()
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, &chainParams)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, &mweb.Recipient{
			Value:   uint64(txOut.Value),
			Address: addrs[0].(*ltcutil.AddressMweb).StealthAddress(),
		})
	}

	if len(coins) == 0 && len(recipients) == 0 {
		return &CreateResponse{RawTx: req.RawTx}, nil
	}

	fee := mweb.EstimateFee(tx.TxOut, ltcutil.Amount(req.FeeRatePerKb), false)
	if sumOutputs+fee > sumCoins {
		pegin = sumOutputs + fee - sumCoins
	}

	tx.Mweb, coins, err =
		mweb.NewTransaction(coins, recipients, fee, pegin, pegouts)
	if err != nil {
		return nil, err
	}

	tx.TxIn = txIns
	tx.TxOut = nil
	if pegin > 0 {
		tx.AddTxOut(mweb.NewPegin(pegin, tx.Mweb.TxBody.Kernels[0]))
	}

	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
		return nil, err
	}

	resp := &CreateResponse{RawTx: buf.Bytes()}
	for _, coin := range coins {
		resp.OutputId = append(resp.OutputId, hex.EncodeToString(coin.OutputId[:]))
	}

	return resp, nil
}
