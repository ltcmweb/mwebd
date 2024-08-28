package mwebd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

	fee := uint64(mweb.StandardOutputWeight)
	fee += mweb.KernelWithStealthWeight * uint64(len(serverPubKeys))
	fee *= mweb.BaseMwebFee

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

	onion, err := makeCoinswapOnion(output, serverPubKeys,
		splitBlind(kernelBlind, len(serverPubKeys)),
		splitBlind(stealthBlind, len(serverPubKeys)))
	if err != nil {
		return nil, err
	}

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
	sig := mw.Sign(coin.SpendKey.Mul((*mw.SecretKey)(h.Sum(nil))), msg.Bytes())
	onion.OwnerProof = sig[:]

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

func makeCoinswapOnion(output *wire.MwebOutput, serverPubKeys [][]byte,
	kernelBlinds, stealthBlinds []*mw.BlindingFactor) (*coinswapOnion, error) {

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	onion := &coinswapOnion{PubKey: privKey.PublicKey().Bytes()}

	var secrets, payloads [][]byte
	for i, pk := range serverPubKeys {
		pubKey, err := x509.ParsePKIXPublicKey(pk)
		if err != nil {
			return nil, err
		}
		secret, err := privKey.ECDH(pubKey.(*ecdh.PublicKey))
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
		if i < len(serverPubKeys)-1 {
			buf.Write(privKey.PublicKey().Bytes())
		} else {
			buf.Write(make([]byte, 32))
		}

		buf.Write(kernelBlinds[i][:])
		buf.Write(stealthBlinds[i][:])

		fee := uint64(mweb.KernelWithStealthWeight)
		if i == len(serverPubKeys)-1 {
			fee += mweb.StandardOutputWeight
		}
		fee *= mweb.BaseMwebFee
		binary.Write(&buf, binary.BigEndian, fee)

		if i == len(serverPubKeys)-1 {
			buf.WriteByte(1)
			output.Serialize(&buf)
		} else {
			buf.WriteByte(0)
		}

		payloads = append(payloads, buf.Bytes())
	}

	for i := len(payloads) - 1; i >= 0; i-- {
		hmac := hmac.New(sha256.New, []byte("MWIXNET"))
		hmac.Write(secrets[i])
		cipher, _ := chacha20.NewUnauthenticatedCipher(hmac.Sum(nil), []byte("NONCE1234567"))
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
