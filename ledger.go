package mwebd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/karalabe/hid"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/secp256k1"
	"lukechampine.com/blake3"
)

type ledger struct{ hid.Device }

func newLedger() (*ledger, error) {
	ds, err := hid.Enumerate(0x2c97, 0)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, errors.New("device not found")
	}
	d, err := ds[0].Open()
	return &ledger{d}, err
}

func (l ledger) send(payload []byte) (resp []byte, err error) {
	const (
		Channel = 0x0101
		Tag     = 0x05
	)
	var (
		i      uint16
		p, r   []byte
		packet [64]byte
	)
	for i = 0; len(payload) > 0; i++ {
		p = packet[:]
		binary.BigEndian.PutUint16(p, Channel)
		p[2] = Tag
		binary.BigEndian.PutUint16(p[3:], i)
		p = p[5:]
		if i == 0 {
			binary.BigEndian.PutUint16(p, uint16(len(payload)))
			p = p[2:]
		}
		payload = payload[copy(p, payload):]
		if _, err = l.Write(packet[:]); err != nil {
			return
		}
	}
	for i = 0; i == 0 || len(r) > 0; i++ {
		var n int
		if n, err = l.Read(packet[:]); err != nil {
			return
		}
		err = errors.New("device read error")
		if n < len(packet) {
			return
		}
		p = packet[:]
		if binary.BigEndian.Uint16(p) != Channel {
			return
		}
		if p[2] != Tag {
			return
		}
		if binary.BigEndian.Uint16(p[3:]) != i {
			return
		}
		p = p[5:]
		if i == 0 {
			resp = make([]byte, binary.BigEndian.Uint16(p))
			p, r = p[2:], resp
		}
		r = r[copy(r, p):]
	}
	if sw := binary.BigEndian.Uint16(resp[len(resp)-2:]); sw != 0x9000 {
		return nil, fmt.Errorf("invalid status %x", sw)
	}
	return resp[:len(resp)-2], nil
}

func ledgerNewTransaction(hdPath []uint32, coins []*mweb.Coin, addrIndex []uint32,
	recipients []*mweb.Recipient, fee, pegin uint64, pegouts []*wire.TxOut) (
	tx *wire.MwebTx, newCoins []*mweb.Coin, err error) {

	const (
		CLA                     = 0xeb
		INS_MWEB_GET_PUBLIC_KEY = 0x05
		INS_MWEB_ADD_INPUT      = 0x07
		INS_MWEB_ADD_OUTPUT     = 0x08
		INS_MWEB_SIGN_OUTPUT    = 0x09
		INS_MWEB_SIGN_KERNEL    = 0x0a
	)

	l, err := newLedger()
	if err != nil {
		return
	}
	defer l.Close()

	buf := []byte{CLA, INS_MWEB_GET_PUBLIC_KEY, 0, 0, 0, byte(len(hdPath))}
	for _, p := range hdPath {
		buf = binary.BigEndian.AppendUint32(buf, p)
	}
	buf[4] = byte(len(buf) - 5)
	if _, err = l.send(buf); err != nil {
		return
	}

	var inputs []*wire.MwebInput
	for i, coin := range coins {
		buf = []byte{CLA, INS_MWEB_ADD_INPUT, 0, 0, 0}
		buf = append(buf, coin.Blind[:]...)
		buf = binary.LittleEndian.AppendUint64(buf, coin.Value)
		buf = append(buf, coin.OutputId[:]...)
		buf = binary.LittleEndian.AppendUint64(buf, uint64(addrIndex[i]))
		buf = append(buf, coin.SharedSecret[:]...)
		buf[4] = byte(len(buf) - 5)
		if buf, err = l.send(buf); err != nil {
			return
		}

		input := struct {
			Features     wire.MwebInputFeatureBit
			OutputId     chainhash.Hash
			Commitment   mw.Commitment
			InputPubKey  mw.PublicKey
			OutputPubKey mw.PublicKey
			Signature    mw.Signature
		}{}
		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &input)
		if err != nil {
			return
		}

		inputs = append(inputs, &wire.MwebInput{
			Features:     input.Features,
			OutputId:     input.OutputId,
			Commitment:   input.Commitment,
			InputPubKey:  &input.InputPubKey,
			OutputPubKey: input.OutputPubKey,
			Signature:    input.Signature,
		})
	}

	var outputs []*wire.MwebOutput
	for _, recipient := range recipients {
		pA, err := secp.ParsePubKey(recipient.Address.A()[:])
		if err != nil {
			return nil, nil, err
		}
		pB, err := secp.ParsePubKey(recipient.Address.B()[:])
		if err != nil {
			return nil, nil, err
		}

		buf = []byte{CLA, INS_MWEB_ADD_OUTPUT, 0, 0, 0}
		buf = binary.LittleEndian.AppendUint64(buf, recipient.Value)
		buf = append(buf, pA.SerializeUncompressed()...)
		buf = append(buf, pB.SerializeUncompressed()...)
		buf[4] = byte(len(buf) - 5)
		if buf, err = l.send(buf); err != nil {
			return nil, nil, err
		}

		result := struct {
			Commitment        mw.Commitment
			SenderPubKey      mw.PublicKey
			ReceiverPubKey    mw.PublicKey
			Features          wire.MwebOutputMessageFeatureBit
			KeyExchangePubKey mw.PublicKey
			ViewTag           byte
			MaskedValue       uint64
			MaskedNonce       [16]byte
			Blind             mw.BlindingFactor
			Shared            mw.SecretKey
		}{}
		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &result)
		if err != nil {
			return nil, nil, err
		}

		output := &wire.MwebOutput{
			Commitment:     result.Commitment,
			SenderPubKey:   result.SenderPubKey,
			ReceiverPubKey: result.ReceiverPubKey,
			Message: wire.MwebOutputMessage{
				Features:          result.Features,
				KeyExchangePubKey: result.KeyExchangePubKey,
				ViewTag:           result.ViewTag,
				MaskedValue:       result.MaskedValue,
				MaskedNonce:       *new(big.Int).SetBytes(result.MaskedNonce[:]),
			},
		}
		outputs = append(outputs, output)

		var messageBuf bytes.Buffer
		output.Message.Serialize(&messageBuf)
		rangeProof := secp256k1.NewRangeProof(recipient.Value,
			*mw.BlindSwitch(&result.Blind, recipient.Value),
			make([]byte, 20), messageBuf.Bytes())
		output.RangeProof = &rangeProof
		output.RangeProofHash = blake3.Sum256(rangeProof[:])

		buf = []byte{CLA, INS_MWEB_SIGN_OUTPUT, 0, 0, 0}
		buf = append(buf, output.RangeProofHash[:]...)
		buf[4] = byte(len(buf) - 5)
		if buf, err = l.send(buf); err != nil {
			return nil, nil, err
		}

		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &output.Signature)
		if err != nil {
			return nil, nil, err
		}

		newCoins = append(newCoins, &mweb.Coin{
			Blind:        &result.Blind,
			Value:        recipient.Value,
			OutputId:     output.Hash(),
			Address:      recipient.Address,
			SharedSecret: &result.Shared,
		})
	}

	buf = []byte{CLA, INS_MWEB_SIGN_KERNEL, 1, 0, 0}
	buf = binary.LittleEndian.AppendUint64(buf, fee)
	buf = binary.LittleEndian.AppendUint64(buf, pegin)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(pegouts)))
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf[4] = byte(len(buf) - 5)
	if _, err = l.send(buf); err != nil {
		return
	}

	for _, pegout := range pegouts {
		buf = []byte{CLA, INS_MWEB_SIGN_KERNEL, 0, 0, 0}
		buf = binary.LittleEndian.AppendUint64(buf, uint64(pegout.Value))
		buf = append(buf, byte(len(pegout.PkScript)))
		buf = append(buf, pegout.PkScript...)
		buf[4] = byte(len(buf) - 5)
		if _, err = l.send(buf); err != nil {
			return
		}
	}

	buf = []byte{CLA, INS_MWEB_SIGN_KERNEL, 0, 0, 1, 0}
	if buf, err = l.send(buf); err != nil {
		return
	}

	result := struct {
		KernelOffset  mw.BlindingFactor
		StealthOffset mw.BlindingFactor
		KernelExcess  mw.Commitment
		StealthExcess mw.PublicKey
		Signature     mw.Signature
	}{}
	err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &result)
	if err != nil {
		return
	}

	tx = &wire.MwebTx{
		KernelOffset:  result.KernelOffset,
		StealthOffset: result.StealthOffset,
		TxBody: &wire.MwebTxBody{
			Inputs:  inputs,
			Outputs: outputs,
			Kernels: []*wire.MwebKernel{{
				Fee:           fee,
				Pegin:         pegin,
				Pegouts:       pegouts,
				Excess:        result.KernelExcess,
				StealthExcess: result.StealthExcess,
				Signature:     result.Signature,
			}},
		},
	}
	return
}
