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
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/ltcwallet/walletdb"
	"github.com/ltcsuite/mwebd/proto"
	"github.com/ltcsuite/neutrino"
	"github.com/ltcsuite/neutrino/mwebdb"
	"google.golang.org/grpc"
)

type Server struct {
	proto.UnimplementedRpcServer
	Port      int
	DB        walletdb.DB
	CS        *neutrino.ChainService
	Log       btclog.Logger
	mtx       sync.Mutex
	server    *grpc.Server
	utxoChan  map[*mw.SecretKey][]chan *proto.Utxo
	coinCache *lru.Cache[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]]
}

func (s *Server) Start() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", s.Port))
	if err != nil {
		s.Log.Errorf("Failed to listen: %v", err)
		return
	}

	s.utxoChan = map[*mw.SecretKey][]chan *proto.Utxo{}
	s.coinCache, _ = lru.New[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]](10)
	s.CS.RegisterMwebUtxosCallback(s.utxoHandler)

	s.server = grpc.NewServer()
	proto.RegisterRpcServer(s.server, s)
	s.server.Serve(lis)
}

func (s *Server) Stop() {
	s.server.Stop()
}

func (s *Server) Status(context.Context,
	*proto.StatusRequest) (*proto.StatusResponse, error) {

	bs, err := s.CS.BestBlock()
	if err != nil {
		return nil, err
	}

	heightMap, err := s.CS.MwebCoinDB.GetLeavesAtHeight()
	if err != nil {
		return nil, err
	}

	var mhHeight uint32
	for height := range heightMap {
		if height > mhHeight {
			mhHeight = height
		}
	}

	lfs, err := s.CS.MwebCoinDB.GetLeafset()
	if err != nil {
		return nil, err
	}

	return &proto.StatusResponse{
		BlockHeaderHeight: bs.Height,
		MwebHeaderHeight:  int32(mhHeight),
		MwebUtxosHeight:   int32(lfs.Height),
	}, nil
}

func (s *Server) utxoHandler(lfs *mweb.Leafset, utxos []*wire.MwebNetUtxo) {
	walletdb.Update(s.DB, func(tx walletdb.ReadWriteTx) error {
		bucket, err := tx.CreateTopLevelBucket([]byte("mweb-mempool"))
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			if utxo.Height == 0 {
				var buf bytes.Buffer
				if err = utxo.Output.Serialize(&buf); err != nil {
					return err
				}
				if err = bucket.Put(utxo.OutputId[:], buf.Bytes()); err != nil {
					return err
				}
			} else if err = bucket.Delete(utxo.OutputId[:]); err != nil {
				return err
			}
		}
		return nil
	})

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
	utxos []*wire.MwebNetUtxo) (result []*proto.Utxo) {

	for _, utxo := range utxos {
		coin, err := s.rewindOutput(utxo.Output, scanSecret)
		if err != nil {
			continue
		}
		chainParams := s.CS.ChainParams()
		addr := ltcutil.NewAddressMweb(coin.Address, &chainParams)
		result = append(result, &proto.Utxo{
			Height:   utxo.Height,
			Value:    coin.Value,
			Address:  addr.String(),
			OutputId: hex.EncodeToString(utxo.OutputId[:]),
		})
	}
	return
}

func (s *Server) Utxos(req *proto.UtxosRequest,
	stream proto.Rpc_UtxosServer) (err error) {

	scanSecret := (*mw.SecretKey)(req.ScanSecret)
	ch, quit := make(chan *proto.Utxo), make(chan *proto.Utxo)
	s.mtx.Lock()
	s.utxoChan[scanSecret] = []chan *proto.Utxo{ch, quit}
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
	req *proto.AddressRequest) (*proto.AddressResponse, error) {

	keychain := &mweb.Keychain{
		Scan:        (*mw.SecretKey)(req.ScanSecret),
		SpendPubKey: (*mw.PublicKey)(req.SpendPubkey),
	}
	resp := &proto.AddressResponse{}
	for i := req.FromIndex; i < req.ToIndex; i++ {
		chainParams := s.CS.ChainParams()
		addr := ltcutil.NewAddressMweb(keychain.Address(i), &chainParams)
		resp.Address = append(resp.Address, addr.String())
	}
	return resp, nil
}

func (s *Server) Spent(ctx context.Context,
	req *proto.SpentRequest) (*proto.SpentResponse, error) {

	resp := &proto.SpentResponse{}
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

func (s *Server) fetchCoin(outputId chainhash.Hash) (*wire.MwebOutput, error) {
	output, err := s.CS.MwebCoinDB.FetchCoin(&outputId)
	if err == mwebdb.ErrCoinNotFound {
		slices.Reverse(outputId[:])
		output, err = s.CS.MwebCoinDB.FetchCoin(&outputId)
	}
	if err == mwebdb.ErrCoinNotFound {
		err = walletdb.View(s.DB, func(tx walletdb.ReadTx) error {
			bucket := tx.ReadBucket([]byte("mweb-mempool"))
			if bucket == nil {
				return err
			}
			b := bucket.Get(outputId[:])
			if b == nil {
				slices.Reverse(outputId[:])
				b = bucket.Get(outputId[:])
			}
			if b == nil {
				return err
			}
			output = &wire.MwebOutput{}
			return output.Deserialize(bytes.NewReader(b))
		})
	}
	return output, err
}

func (s *Server) rewindOutput(output *wire.MwebOutput,
	scanSecret *mw.SecretKey) (coin *mweb.Coin, err error) {

	cache, ok := s.coinCache.Get(*scanSecret)
	if !ok {
		cache, _ = lru.New[chainhash.Hash, *mweb.Coin](100)
		s.coinCache.Add(*scanSecret, cache)
	}
	coin, ok = cache.Get(*output.Hash())
	if !ok {
		coin, err = mweb.RewindOutput(output, scanSecret)
		if err == nil {
			cache.Add(*output.Hash(), coin)
		}
	}
	if coin != nil {
		c := mweb.Coin(*coin)
		coin = &c
	}
	return
}

func (s *Server) Create(ctx context.Context,
	req *proto.CreateRequest) (*proto.CreateResponse, error) {

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

	keychain := &mweb.Keychain{
		Scan:  (*mw.SecretKey)(req.ScanSecret),
		Spend: (*mw.SecretKey)(req.SpendSecret),
	}

	for _, txIn := range tx.TxIn {
		output, err := s.fetchCoin(txIn.PreviousOutPoint.Hash)
		switch err {
		case nil:
			coin, err := s.rewindOutput(output, keychain.Scan)
			if err != nil {
				return nil, err
			}

			coin.CalculateOutputKey(keychain.SpendKey(txIn.PreviousOutPoint.Index))
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
		return &proto.CreateResponse{RawTx: req.RawTx}, nil
	}

	fee := mweb.EstimateFee(tx.TxOut, ltcutil.Amount(req.FeeRatePerKb), false)
	if sumOutputs+fee > sumCoins {
		pegin = sumOutputs + fee - sumCoins
	} else {
		fee = sumCoins - sumOutputs
	}

	if !req.DryRun {
		tx.Mweb, coins, err =
			mweb.NewTransaction(coins, recipients, fee, pegin, pegouts)
		if err != nil {
			return nil, err
		}
	} else {
		tx.Mweb = &wire.MwebTx{
			TxBody: &wire.MwebTxBody{
				Kernels: []*wire.MwebKernel{{}},
			},
		}
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

	resp := &proto.CreateResponse{RawTx: buf.Bytes()}
	for _, coin := range coins {
		resp.OutputId = append(resp.OutputId, hex.EncodeToString(coin.OutputId[:]))
	}

	return resp, nil
}

func (s *Server) Broadcast(ctx context.Context,
	req *proto.BroadcastRequest) (*proto.BroadcastResponse, error) {

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(req.RawTx)); err != nil {
		return nil, err
	}
	if err := s.CS.SendTransaction(&tx); err != nil {
		return nil, err
	}

	if tx.Mweb != nil {
		var utxos []*wire.MwebNetUtxo
		for _, output := range tx.Mweb.TxBody.Outputs {
			utxos = append(utxos, &wire.MwebNetUtxo{
				Output:   output,
				OutputId: output.Hash(),
			})
		}
		go s.utxoHandler(nil, utxos)
	}

	return &proto.BroadcastResponse{Txid: tx.TxHash().String()}, nil
}
