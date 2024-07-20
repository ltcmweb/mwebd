package ledger

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/secp256k1"
	"lukechampine.com/blake3"
)

type mwebAddOutputState struct{ index int }

func (st *mwebAddOutputState) request(ctx *TxContext) []byte {
	recipient := ctx.Recipients[st.index]
	pA, _ := secp.ParsePubKey(recipient.Address.A()[:])
	pB, _ := secp.ParsePubKey(recipient.Address.B()[:])
	buf := []byte{CLA, INS_MWEB_ADD_OUTPUT, 0, 0, 0}
	buf = binary.LittleEndian.AppendUint64(buf, recipient.Value)
	buf = append(buf, pA.SerializeUncompressed()...)
	buf = append(buf, pB.SerializeUncompressed()...)
	return buf
}

func (st *mwebAddOutputState) process(ctx *TxContext, r io.Reader) (txState, error) {
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
	err := binary.Read(r, binary.LittleEndian, &result)
	if err != nil {
		return nil, err
	}
	message := wire.MwebOutputMessage{
		Features:          result.Features,
		KeyExchangePubKey: result.KeyExchangePubKey,
		ViewTag:           result.ViewTag,
		MaskedValue:       result.MaskedValue,
		MaskedNonce:       *new(big.Int).SetBytes(result.MaskedNonce[:]),
	}
	var msg bytes.Buffer
	message.Serialize(&msg)
	recipient := ctx.Recipients[st.index]
	rangeProof := secp256k1.NewRangeProof(recipient.Value,
		*mw.BlindSwitch(&result.Blind, recipient.Value),
		make([]byte, 20), msg.Bytes())
	ctx.outputs = append(ctx.outputs, &wire.MwebOutput{
		Commitment:     result.Commitment,
		SenderPubKey:   result.SenderPubKey,
		ReceiverPubKey: result.ReceiverPubKey,
		Message:        message,
		RangeProof:     &rangeProof,
		RangeProofHash: blake3.Sum256(rangeProof[:]),
	})
	ctx.NewCoins = append(ctx.NewCoins, &mweb.Coin{
		Blind:        &result.Blind,
		Value:        recipient.Value,
		Address:      recipient.Address,
		SharedSecret: &result.Shared,
	})
	return &mwebSignOutputState{st.index}, nil
}
