package mwebd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/config"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
)

func (s *Server) Coinswap(ctx context.Context,
	req *proto.CoinswapRequest) (*proto.CoinswapResponse, error) {

	nodes := config.AliveNodes(ctx, nil)
	if len(nodes) == 0 {
		return nil, errors.New("no alive nodes")
	}

	keychain := &mweb.Keychain{
		Scan:  (*mw.SecretKey)(req.ScanSecret),
		Spend: (*mw.SecretKey)(req.SpendSecret),
	}

	outputId, err := hex.DecodeString(req.OutputId)
	if err != nil {
		return nil, err
	}

	output, err := s.fetchCoin(chainhash.Hash(outputId))
	if err != nil {
		return nil, err
	}

	coin, err := s.rewindOutput(output, keychain.Scan)
	if err != nil {
		return nil, err
	}
	coin.CalculateOutputKey(keychain.SpendKey(req.AddrIndex))

	var hops []*onion.Hop
	for _, node := range nodes {
		fee := mweb.StandardOutputWeight * mweb.BaseMwebFee
		fee = (fee + len(nodes) - 1) / len(nodes)
		fee += mweb.KernelWithStealthWeight * mweb.BaseMwebFee
		hops = append(hops, &onion.Hop{PubKey: node.PubKey(), Fee: uint64(fee)})
	}

	var fee uint64
	for _, hop := range hops {
		fee += hop.Fee
	}
	if coin.Value < fee {
		return nil, errors.New("insufficient value for fee")
	}

	recipient := &mweb.Recipient{
		Value:   coin.Value - fee,
		Address: coin.Address,
	}

	input, output, kernelBlind, stealthBlind, err := makeCoinswapTx(coin, recipient)
	if err != nil {
		return nil, err
	}

	for i, blind := range splitBlind(kernelBlind, len(hops)) {
		hops[i].KernelBlind = *blind
	}
	for i, blind := range splitBlind(stealthBlind, len(hops)) {
		hops[i].StealthBlind = *blind
	}

	hops[len(hops)-1].Output = output

	onion, err := onion.New(hops)
	if err != nil {
		return nil, err
	}
	onion.Sign(input, coin.SpendKey)

	client, err := rpc.DialContext(ctx, nodes[0].Url)
	if err != nil {
		return nil, err
	}
	if err = client.CallContext(ctx, nil, "swap_swap", onion); err != nil {
		return nil, err
	}

	return &proto.CoinswapResponse{}, nil
}

func makeCoinswapTx(coin *mweb.Coin, recipient *mweb.Recipient) (
	input *wire.MwebInput, output *wire.MwebOutput,
	kernelBlind, stealthBlind *mw.BlindingFactor, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = errors.New("input coins are bad")
		}
	}()

	var inputKey, outputKey mw.SecretKey
	if _, err = rand.Read(inputKey[:]); err != nil {
		return
	}
	if _, err = rand.Read(outputKey[:]); err != nil {
		return
	}

	input = mweb.CreateInput(coin, &inputKey)
	inputBlind := mw.BlindSwitch(coin.Blind, coin.Value)

	output, blind, _ := mweb.CreateOutput(recipient, &outputKey)
	mweb.SignOutput(output, recipient.Value, blind, &outputKey)
	outputBlind := mw.BlindSwitch(blind, recipient.Value)

	kernelBlind = outputBlind.Sub(inputBlind)
	stealthBlind = (*mw.BlindingFactor)(outputKey.Add(&inputKey).Sub(coin.SpendKey))
	return
}

func splitBlind(blind *mw.BlindingFactor, n int) (blinds []*mw.BlindingFactor) {
	for ; n > 1; n-- {
		var x mw.BlindingFactor
		if _, err := rand.Read(x[:]); err != nil {
			panic(err)
		}
		blinds = append(blinds, &x)
		blind = blind.Sub(&x)
	}
	blinds = append(blinds, blind)
	return
}
