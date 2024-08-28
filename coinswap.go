package mwebd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
	"golang.org/x/crypto/chacha20"
	"lukechampine.com/blake3"
)

type (
	coinswapHop struct {
		pubKey       *ecdh.PublicKey
		kernelBlind  *mw.BlindingFactor
		stealthBlind *mw.BlindingFactor
		fee          uint64
	}
	coinswapOnion struct {
		Input struct {
			OutputId     hexBytes `json:"output_id"`
			Commitment   hexBytes `json:"output_commit"`
			OutputPubKey hexBytes `json:"output_pk"`
			InputPubKey  hexBytes `json:"input_pk"`
			Signature    hexBytes `json:"input_sig"`
		}
		Payloads   hexBytes `json:"enc_payloads"`
		PubKey     hexBytes `json:"ephemeral_xpub"`
		OwnerProof hexBytes `json:"owner_proof"`
	}
	hexBytes []byte
)

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (s *Server) Coinswap(ctx context.Context,
	req *proto.CoinswapRequest) (*proto.CoinswapResponse, error) {

	serverPubKeys := [][]byte{}

	keychain := &mweb.Keychain{
		Scan:  (*mw.SecretKey)(req.ScanSecret),
		Spend: (*mw.SecretKey)(req.SpendSecret),
	}

	b, err := hex.DecodeString(req.OutputId)
	if err != nil {
		return nil, err
	}

	output, err := s.fetchCoin(chainhash.Hash(b))
	if err != nil {
		return nil, err
	}

	coin, err := s.rewindOutput(output, keychain.Scan)
	if err != nil {
		return nil, err
	}
	coin.CalculateOutputKey(keychain.SpendKey(req.AddrIndex))

	var hops []*coinswapHop
	for _, pk := range serverPubKeys {
		pubKey, err := ecdh.X25519().NewPublicKey(pk)
		if err != nil {
			return nil, err
		}
		hops = append(hops, &coinswapHop{
			pubKey: pubKey,
			fee:    mweb.KernelWithStealthWeight * mweb.BaseMwebFee,
		})
	}
	hops[len(hops)-1].fee += mweb.StandardOutputWeight * mweb.BaseMwebFee

	var fee uint64
	for _, hop := range hops {
		fee += hop.fee
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
		hops[i].kernelBlind = blind
	}
	for i, blind := range splitBlind(stealthBlind, len(hops)) {
		hops[i].stealthBlind = blind
	}

	onion, err := makeCoinswapOnion(hops, output)
	if err != nil {
		return nil, err
	}

	signCoinswapOnion(onion, input, coin.SpendKey)

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

func makeCoinswapOnion(hops []*coinswapHop,
	output *wire.MwebOutput) (*coinswapOnion, error) {

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	onion := &coinswapOnion{PubKey: privKey.PublicKey().Bytes()}

	var secrets, payloads [][]byte
	for i, hop := range hops {
		secret, err := privKey.ECDH(hop.pubKey)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)

		privKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		buf.WriteByte(0)
		if i < len(hops)-1 {
			buf.Write(privKey.PublicKey().Bytes())
		} else {
			buf.Write(make([]byte, 32))
		}

		buf.Write(hop.kernelBlind[:])
		buf.Write(hop.stealthBlind[:])
		binary.Write(&buf, binary.BigEndian, hop.fee)

		if i == len(hops)-1 {
			buf.WriteByte(1)
			output.Serialize(&buf)
		} else {
			buf.WriteByte(0)
		}

		payloads = append(payloads, buf.Bytes())
	}

	for i := len(payloads) - 1; i >= 0; i-- {
		cipher := newOnionCipher(secrets[i])
		for j := i; j < len(payloads); j++ {
			cipher.XORKeyStream(payloads[j], payloads[j])
		}
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint64(len(payloads)))
	for _, payload := range payloads {
		binary.Write(&buf, binary.BigEndian, uint64(len(payload)))
		buf.Write(payload)
	}
	onion.Payloads = buf.Bytes()
	return onion, nil
}

func newOnionCipher(secret []byte) *chacha20.Cipher {
	h := hmac.New(sha256.New, []byte("MWIXNET"))
	h.Write(secret)
	cipher, _ := chacha20.NewUnauthenticatedCipher(h.Sum(nil), []byte("NONCE1234567"))
	return cipher
}

func signCoinswapOnion(onion *coinswapOnion,
	input *wire.MwebInput, spendKey *mw.SecretKey) {

	onion.Input.OutputId = input.OutputId[:]
	onion.Input.Commitment = input.Commitment[:]
	onion.Input.OutputPubKey = input.OutputPubKey[:]
	onion.Input.InputPubKey = input.InputPubKey[:]
	onion.Input.Signature = input.Signature[:]

	var msg bytes.Buffer
	msg.Write(onion.Input.OutputId)
	msg.Write(onion.Input.Commitment)
	msg.Write(onion.Input.OutputPubKey)
	msg.Write(onion.Input.InputPubKey)
	msg.Write(onion.Input.Signature)
	msg.Write(onion.Payloads)
	msg.Write(onion.PubKey)

	h := blake3.New(32, nil)
	h.Write(input.InputPubKey[:])
	h.Write(input.OutputPubKey[:])
	sig := mw.Sign(spendKey.Mul((*mw.SecretKey)(h.Sum(nil))), msg.Bytes())
	onion.OwnerProof = sig[:]
}
