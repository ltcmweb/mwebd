package mwebd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
	"github.com/ltcmweb/neutrino"
	"github.com/ltcmweb/neutrino/mwebdb"
	"github.com/ltcsuite/ltcwallet/walletdb"
	_ "github.com/ltcsuite/ltcwallet/walletdb/bdb"
	"google.golang.org/grpc"
)

type Server struct {
	proto.UnimplementedRpcServer
	db        walletdb.DB
	cs        *neutrino.ChainService
	mtx       sync.Mutex
	server    *grpc.Server
	utxoChan  map[*mw.SecretKey][]chan *proto.Utxo
	coinCache *lru.Cache[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]]
}

func NewServer(chain, dataDir, peer string) (s *Server, err error) {
	s = &Server{}
	s.utxoChan = map[*mw.SecretKey][]chan *proto.Utxo{}
	s.coinCache, _ = lru.New[mw.SecretKey, *lru.Cache[chainhash.Hash, *mweb.Coin]](10)

	s.db, err = walletdb.Create(
		"bdb", filepath.Join(dataDir, "neutrino.db"), false, time.Minute)
	if err != nil {
		return
	}

	cfg := neutrino.Config{
		DataDir:     dataDir,
		Database:    s.db,
		ChainParams: chaincfg.MainNetParams,
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

	s.cs, err = neutrino.NewChainService(cfg)
	if err != nil {
		return
	}

	s.cs.RegisterMwebUtxosCallback(s.utxoHandler)
	return s, s.cs.Start()
}

func (s *Server) Start(port int) (int, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return 0, err
	}

	s.server = grpc.NewServer()
	proto.RegisterRpcServer(s.server, s)

	if port == 0 {
		go s.serve(lis)
		return lis.Addr().(*net.TCPAddr).Port, nil
	}
	return port, s.serve(lis)
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
	ch, quit := make(chan *proto.Utxo), make(chan *proto.Utxo)
	s.mtx.Lock()
	s.utxoChan[scanSecret] = []chan *proto.Utxo{ch, quit}
	s.mtx.Unlock()

	defer func() {
		close(quit)
		s.mtx.Lock()
		delete(s.utxoChan, scanSecret)
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

	lfs, err := s.cs.MwebCoinDB.GetLeafset()
	if err != nil {
		return
	}
	for leaves := []uint64{}; leaf < lfs.Size; leaf++ {
		if lfs.Contains(leaf) {
			leaves = append(leaves, leaf)
		}
		if len(leaves) == 1000 || leaf == lfs.Size-1 {
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
	err = stream.Send(&proto.Utxo{})
	for ; err == nil; err = stream.Send(<-ch) {
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

func (s *Server) LedgerKeys(ctx context.Context,
	req *proto.LedgerKeysRequest) (*proto.LedgerKeysResponse, error) {

	const (
		CLA = 0xeb
		INS = 0x05
	)
	l, err := newLedger()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	buf := []byte{CLA, INS, 0, 0, 0, byte(len(req.HdPath))}
	for _, p := range req.HdPath {
		buf = binary.BigEndian.AppendUint32(buf, p)
	}
	if req.ConfirmAddress {
		buf[2]++
		buf[5]--
	}
	buf[4] = byte(len(buf) - 5)
	if buf, err = l.send(buf); err != nil {
		return nil, err
	}
	data := struct {
		Scan  mw.SecretKey
		Spend mw.PublicKey
	}{}
	err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &data)
	if err != nil {
		return nil, err
	}
	return &proto.LedgerKeysResponse{
		ScanSecret:  data.Scan[:],
		SpendPubkey: data.Spend[:],
	}, nil
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
		var fn mweb.CreateInputsAndKernelFunc
		if bytes.Count(req.SpendSecret, []byte{0}) == len(req.SpendSecret) {
			fn = s.sendLedger(req.HdPath, coins, addrIndex, fee, pegin, pegouts)
		}
		tx.Mweb, coins, err = mweb.NewTransaction(
			coins, recipients, fee, pegin, pegouts, fn)
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

func (s *Server) sendLedger(hdPath []uint32, coins []*mweb.Coin,
	addrIndex []uint32, fee, pegin uint64, pegouts []*wire.TxOut,
) mweb.CreateInputsAndKernelFunc {

	return func(outputKey *mw.SecretKey, kernelBlind *mw.BlindingFactor) (
		inputs []*wire.MwebInput, kernel *wire.MwebKernel,
		stealthOffset *mw.BlindingFactor, err error) {

		const (
			CLA     = 0xeb
			INS     = 0x06
			P2_MORE = 0x80
		)
		kernel = mweb.CreateKernel(kernelBlind, nil, &fee, &pegin, pegouts, nil)
		l, err := newLedger()
		if err != nil {
			return
		}
		defer l.Close()
		buf := []byte{CLA, INS, 0, P2_MORE, 0, byte(len(hdPath))}
		for _, p := range hdPath {
			buf = binary.BigEndian.AppendUint32(buf, p)
		}
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(coins)))
		buf = append(buf, outputKey[:]...)
		buf = append(buf, kernelBlind[:]...)
		buf = append(buf, kernel.Excess.PubKey()[:]...)
		buf[4] = byte(len(buf) - 5)
		if _, err = l.send(buf); err != nil {
			return
		}
		for i, coin := range coins {
			buf = []byte{CLA, INS, 1, 0, 0}
			buf = append(buf, coin.OutputId[:]...)
			buf = binary.LittleEndian.AppendUint32(buf, addrIndex[i])
			buf = append(buf, coin.SharedSecret[:]...)
			buf = append(buf, coin.SpendKey[:]...)
			buf[4] = byte(len(buf) - 5)
			if buf, err = l.send(buf); err != nil {
				return
			}
			input := struct {
				Features     byte
				OutputId     chainhash.Hash
				InputPubKey  mw.PublicKey
				OutputPubKey mw.PublicKey
				Signature    mw.Signature
			}{}
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &input)
			if err != nil {
				return
			}
			inputs = append(inputs, &wire.MwebInput{
				Features:     wire.MwebInputFeatureBit(input.Features),
				OutputId:     input.OutputId,
				InputPubKey:  &input.InputPubKey,
				OutputPubKey: input.OutputPubKey,
				Signature:    input.Signature,
			})
		}
		msg := kernel.Message()
		msg[0] |= byte(wire.MwebKernelStealthExcessFeatureBit)
		for n := 200; len(msg) > n; msg = msg[n:] {
			buf = []byte{CLA, INS, 1, P2_MORE, byte(n)}
			buf = append(buf, msg[:n]...)
			if _, err = l.send(buf); err != nil {
				return
			}
		}
		buf = []byte{CLA, INS, 1, 0, byte(len(msg))}
		buf = append(buf, msg...)
		if buf, err = l.send(buf); err != nil {
			return
		}
		data := struct {
			StealthOffset   mw.BlindingFactor
			StealthExcess   mw.PublicKey
			KernelSignature mw.Signature
		}{}
		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &data)
		if err != nil {
			return
		}
		stealthOffset = &data.StealthOffset
		kernel.Features |= wire.MwebKernelStealthExcessFeatureBit
		kernel.StealthExcess = data.StealthExcess
		kernel.Signature = data.KernelSignature
		return
	}
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
