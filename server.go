package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btclog"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/ledger"
	"github.com/ltcmweb/mwebd/proto"
	"github.com/ltcmweb/neutrino"
	"github.com/ltcmweb/neutrino/mwebdb"
	"github.com/ltcsuite/ltcwallet/walletdb"
	_ "github.com/ltcsuite/ltcwallet/walletdb/bdb"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Server struct {
	proto.UnimplementedRpcServer
	db        walletdb.DB
	cs        *neutrino.ChainService
	mtx       sync.Mutex
	server    *grpc.Server
	utxoChan  map[mw.SecretKey]map[*utxoStreamer]struct{}
	coinCache *lru.Cache[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]]
	ledgerTx  *ledger.TxContext
}

func NewServer(chain, dataDir, peer string, proxy_addr string) (s *Server, err error) {
	s = &Server{}
	s.utxoChan = map[mw.SecretKey]map[*utxoStreamer]struct{}{}
	s.coinCache, _ = lru.New[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]](10)

	s.db, err = walletdb.Create(
		"bdb", filepath.Join(dataDir, "neutrino.db"), false, time.Minute)
	if err != nil {
		return
	}

	var dialer func(net.Addr) (net.Conn, error)
	if len(proxy_addr) != 0 {
		url, err := url.ParseRequestURI(proxy_addr)
		if err != nil {
			return nil, err
		}
		proxy_dialer, err := proxy.FromURL(url, proxy.Direct)
		if err != nil {
			return nil, err
		}

		dialer = func(addr net.Addr) (net.Conn, error) {
			return proxy_dialer.Dial("tcp", addr.String())
		}
	} else {
		dialer = func(addr net.Addr) (net.Conn, error) {
			return net.Dial("tcp", addr.String())
		}

	}

	cfg := neutrino.Config{
		DataDir:     dataDir,
		Database:    s.db,
		ChainParams: chaincfg.MainNetParams,
		Dialer:      dialer,
	}

	switch chain {
	case "testnet":
		cfg.ChainParams = chaincfg.TestNet4Params
	case "regtest":
		cfg.ChainParams = chaincfg.RegressionNetParams
	}

	if peer != "" {
		cfg.AddPeers = []string{peer}
	}

	log := btclog.NewBackend(&lumberjack.Logger{
		Filename:   filepath.Join(dataDir, "logs", "debug.log"),
		MaxSize:    10,
		MaxBackups: 10,
		Compress:   true,
	}).Logger("")
	log.SetLevel(btclog.LevelDebug)
	neutrino.UseLogger(log)

	s.cs, err = neutrino.NewChainService(cfg)
	if err != nil {
		return
	}

	s.cs.RegisterMwebUtxosCallback(s.utxoHandler)
	return s, s.cs.Start()
}

func (s *Server) Start(port int) (int, error) {
	return s.StartAddr(fmt.Sprintf("127.0.0.1:%d", port))
}

func (s *Server) StartAddr(addr string) (int, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, err
	}

	s.server = grpc.NewServer()
	proto.RegisterRpcServer(s.server, s)

	if addr[len(addr)-2:] == ":0" {
		go s.serve(lis)
		return lis.Addr().(*net.TCPAddr).Port, nil
	}
	return 0, s.serve(lis)
}

func (s *Server) serve(lis net.Listener) error {
	if err := s.server.Serve(lis); err != nil {
		return err
	}
	if err := s.cs.Stop(); err != nil {
		return err
	}
	return s.db.Close()
}

func (s *Server) Stop() {
	s.server.Stop()
}

func (s *Server) Status(context.Context,
	*proto.StatusRequest) (*proto.StatusResponse, error) {

	bh, bhHeight, err := s.cs.BlockHeaders.ChainTip()
	if err != nil {
		return nil, err
	}

	heightMap, err := s.cs.MwebCoinDB.GetLeavesAtHeight()
	if err != nil {
		return nil, err
	}

	var mhHeight uint32
	for height := range heightMap {
		if height > mhHeight {
			mhHeight = height
		}
	}

	lfs, err := s.cs.MwebCoinDB.GetLeafset()
	if err != nil {
		return nil, err
	}

	return &proto.StatusResponse{
		BlockHeaderHeight: int32(bhHeight),
		MwebHeaderHeight:  int32(mhHeight),
		MwebUtxosHeight:   int32(lfs.Height),
		BlockTime:         uint32(bh.Timestamp.Unix()),
	}, nil
}

func (s *Server) utxoHandler(lfs *mweb.Leafset, utxos []*wire.MwebNetUtxo) {
	walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
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

	var leaves []uint64
	for _, utxo := range utxos {
		if utxo.Height > 0 {
			leaves = append(leaves, utxo.LeafIndex)
		}
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	for scanSecret, us := range s.utxoChan {
		utxos := s.filterUtxos(&scanSecret, utxos)
		for u := range us {
			u.notify(lfs, utxos, leaves)
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
		chainParams := s.cs.ChainParams()
		addr := ltcutil.NewAddressMweb(coin.Address, &chainParams)
		bh, err := s.cs.BlockHeaders.FetchHeaderByHeight(uint32(utxo.Height))
		if err != nil {
			bh = &wire.BlockHeader{Timestamp: time.Unix(0, 0)}
		}
		result = append(result, &proto.Utxo{
			Height:    utxo.Height,
			Value:     coin.Value,
			Address:   addr.String(),
			OutputId:  hex.EncodeToString(utxo.OutputId[:]),
			BlockTime: uint32(bh.Timestamp.Unix()),
		})
	}
	return
}

func (s *Server) Utxos(req *proto.UtxosRequest,
	stream proto.Rpc_UtxosServer) (err error) {

	scanSecret := (*mw.SecretKey)(req.ScanSecret)
	u := s.newUtxoStreamer(scanSecret)
	s.mtx.Lock()
	if s.utxoChan[*scanSecret] == nil {
		s.utxoChan[*scanSecret] = map[*utxoStreamer]struct{}{}
	}
	s.utxoChan[*scanSecret][u] = struct{}{}
	s.mtx.Unlock()

	defer func() {
		close(u.quit)
		s.mtx.Lock()
		delete(s.utxoChan[*scanSecret], u)
		if len(s.utxoChan[*scanSecret]) == 0 {
			delete(s.utxoChan, *scanSecret)
		}
		s.mtx.Unlock()
	}()

	heightMap, err := s.cs.MwebCoinDB.GetLeavesAtHeight()
	if err != nil {
		return
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

	u.lfs, err = s.cs.MwebCoinDB.GetLeafset()
	if err != nil {
		return
	}
	for leaves := []uint64{}; leaf < u.lfs.Size; leaf++ {
		if u.lfs.Contains(leaf) {
			leaves = append(leaves, leaf)
		}
		if len(leaves) == 1000 || leaf == u.lfs.Size-1 {
			utxos, err := s.cs.MwebCoinDB.FetchLeaves(leaves)
			if err != nil {
				return err
			}
			for _, utxo := range s.filterUtxos(scanSecret, utxos) {
				if err = stream.Send(utxo); err != nil {
					return err
				}
			}
			leaves = leaves[:0]
		}
	}
	for ; err == nil; err = stream.Send(<-u.ch) {
	}
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
		chainParams := s.cs.ChainParams()
		addr := ltcutil.NewAddressMweb(keychain.Address(i), &chainParams)
		resp.Address = append(resp.Address, addr.String())
	}
	return resp, nil
}

func Addresses(scanSecret, spendPubKey []byte, i, j int32) string {
	keychain := &mweb.Keychain{
		Scan:        (*mw.SecretKey)(scanSecret),
		SpendPubKey: (*mw.PublicKey)(spendPubKey),
	}
	var sb strings.Builder
	for ; i < j; i++ {
		if sb.Len() > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(ltcutil.NewAddressMweb(keychain.Address(uint32(i)),
			&chaincfg.MainNetParams).String())
	}
	return sb.String()
}

func (s *Server) Spent(ctx context.Context,
	req *proto.SpentRequest) (*proto.SpentResponse, error) {

	resp := &proto.SpentResponse{}
	for _, outputIdStr := range req.OutputId {
		outputId, err := hex.DecodeString(outputIdStr)
		if err != nil {
			return nil, err
		}
		if !s.cs.MwebUtxoExists((*chainhash.Hash)(outputId)) {
			resp.OutputId = append(resp.OutputId, outputIdStr)
		}
	}
	return resp, nil
}

func (s *Server) fetchCoin(outputId chainhash.Hash) (*wire.MwebOutput, error) {
	output, err := s.cs.MwebCoinDB.FetchCoin(&outputId)
	if err == mwebdb.ErrCoinNotFound {
		slices.Reverse(outputId[:])
		output, err = s.cs.MwebCoinDB.FetchCoin(&outputId)
	}
	if err == mwebdb.ErrCoinNotFound {
		err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
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
		addrIndex  []uint32
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

			index := txIn.PreviousOutPoint.Index
			coin.CalculateOutputKey(keychain.SpendKey(index))
			coins = append(coins, coin)
			addrIndex = append(addrIndex, index)
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

		chainParams := s.cs.ChainParams()
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
		if *keychain.Spend == (mw.SecretKey{}) {
			if s.ledgerTx == nil || s.ledgerTx.Tx == nil {
				s.ledgerTx = &ledger.TxContext{
					Coins:      coins,
					AddrIndex:  addrIndex,
					Recipients: recipients,
					Fee:        fee,
					Pegin:      pegin,
					Pegouts:    pegouts,
				}
				return &proto.CreateResponse{}, nil
			}
			tx.Mweb = s.ledgerTx.Tx
			coins = s.ledgerTx.NewCoins
			s.ledgerTx = nil
		} else {
			tx.Mweb, coins, err = mweb.NewTransaction(
				coins, recipients, fee, pegin, pegouts, nil, nil)
		}
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

func (s *Server) LedgerExchange(ctx context.Context,
	req *proto.LedgerApdu) (*proto.LedgerApdu, error) {

	if s.ledgerTx == nil {
		return nil, errors.New("nil ledger tx")
	}
	if err := s.ledgerTx.Process(req.Data); err != nil {
		return nil, err
	}
	if s.ledgerTx.Tx != nil {
		return &proto.LedgerApdu{}, nil
	}
	return &proto.LedgerApdu{Data: s.ledgerTx.Request()}, nil
}

func (s *Server) Broadcast(ctx context.Context,
	req *proto.BroadcastRequest) (*proto.BroadcastResponse, error) {

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(req.RawTx)); err != nil {
		return nil, err
	}
	if err := s.cs.SendTransaction(&tx); err != nil {
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
