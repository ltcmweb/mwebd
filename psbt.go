package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/ltcutil/psbt"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
)

func (s *Server) PsbtCreate(ctx context.Context,
	req *proto.PsbtCreateRequest) (*proto.PsbtResponse, error) {

	tx := wire.NewMsgTx(2)
	if req.RawTx != nil {
		if err := tx.Deserialize(bytes.NewReader(req.RawTx)); err != nil {
			return nil, err
		}
	}

	p := &psbt.Packet{
		PsbtVersion:      2,
		TxVersion:        tx.Version,
		FallbackLocktime: &tx.LockTime,
	}
	for _, txIn := range tx.TxIn {
		p.Inputs = append(p.Inputs, psbt.PInput{
			PrevoutHash:  &txIn.PreviousOutPoint.Hash,
			PrevoutIndex: &txIn.PreviousOutPoint.Index,
			Sequence:     &txIn.Sequence,
		})
	}
	for _, txOut := range tx.TxOut {
		p.Outputs = append(p.Outputs, psbt.POutput{
			Amount:   ltcutil.Amount(txOut.Value),
			PKScript: txOut.PkScript,
		})
	}

	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) PsbtAddInput(ctx context.Context,
	req *proto.PsbtAddInputRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	outputId, err := hex.DecodeString(req.OutputId)
	if err != nil {
		return nil, err
	}

	output, err := s.fetchCoin(chainhash.Hash(outputId))
	if err != nil {
		return nil, err
	}

	coin, err := s.rewindOutput(output, (*mw.SecretKey)(req.ScanSecret))
	if err != nil {
		return nil, err
	}

	amount := ltcutil.Amount(coin.Value)

	p.Inputs = append(p.Inputs, psbt.PInput{
		MwebOutputId:          (*chainhash.Hash)(outputId),
		MwebAddressIndex:      &req.AddressIndex,
		MwebAmount:            &amount,
		MwebSharedSecret:      coin.SharedSecret,
		MwebKeyExchangePubkey: &output.Message.KeyExchangePubKey,
		MwebCommit:            &output.Commitment,
		MwebOutputPubkey:      &output.ReceiverPubKey,
	})

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) getKernelIndex(p *psbt.Packet) (index int) {
	for _, pKernel := range p.Kernels {
		if pKernel.Signature == nil {
			break
		}
		index++
	}
	if index == len(p.Kernels) {
		fee := ltcutil.Amount(mweb.KernelWithStealthWeight * mweb.BaseMwebFee)
		pKernel := psbt.PKernel{Fee: &fee}
		if p.FallbackLocktime != nil &&
			*p.FallbackLocktime > 0 &&
			*p.FallbackLocktime < 500_000_000 {
			lockHeight := int32(*p.FallbackLocktime)
			pKernel.LockHeight = &lockHeight
		}
		p.Kernels = append(p.Kernels, pKernel)
	}
	return
}

func (s *Server) PsbtAddRecipient(ctx context.Context,
	req *proto.PsbtAddRecipientRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	p.Outputs = append(p.Outputs, psbt.POutput{
		Amount: ltcutil.Amount(req.Value),
		StealthAddress: &mw.StealthAddress{
			Scan:  (*mw.PublicKey)(req.ScanPubkey),
			Spend: (*mw.PublicKey)(req.SpendPubkey),
		},
	})

	index := s.getKernelIndex(p)
	*p.Kernels[index].Fee += mweb.StandardOutputWeight * mweb.BaseMwebFee

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) PsbtAddPegout(ctx context.Context,
	req *proto.PsbtAddPegoutRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	index := s.getKernelIndex(p)
	txOut := wire.NewTxOut(req.Value, req.PkScript)
	p.Kernels[index].PegOuts = append(p.Kernels[index].PegOuts, txOut)

	fee := ltcutil.Amount(math.Ceil(float64(req.FeeRatePerKb) *
		float64(txOut.SerializeSize()) / 1000))
	fee += ltcutil.Amount(len(req.PkScript)+mweb.BytesPerWeight-1) /
		mweb.BytesPerWeight * mweb.BaseMwebFee
	*p.Kernels[index].Fee += fee

	s.addPeginIfNecessary(p)

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) addPeginIfNecessary(p *psbt.Packet) {
	var offset ltcutil.Amount

	for _, pInput := range p.Inputs {
		if pInput.MwebAmount != nil {
			offset -= *pInput.MwebAmount
		}
	}
	for _, pOutput := range p.Outputs {
		if pOutput.StealthAddress != nil || pOutput.OutputCommit != nil {
			offset += pOutput.Amount
		}
	}

	for _, pKernel := range p.Kernels {
		if pKernel.Fee != nil {
			offset += *pKernel.Fee
		}
		if pKernel.PeginAmount != nil {
			offset -= *pKernel.PeginAmount
		}
		for _, pegout := range pKernel.PegOuts {
			offset += ltcutil.Amount(pegout.Value)
		}
	}

	kernel := &p.Kernels[s.getKernelIndex(p)]
	if offset > 0 {
		if kernel.PeginAmount == nil {
			kernel.PeginAmount = new(ltcutil.Amount)
		}
		*kernel.PeginAmount += offset
	} else {
		for _, pKernel := range p.Kernels {
			if pKernel.Signature == nil && pKernel.PeginAmount != nil {
				if *pKernel.PeginAmount <= -offset {
					offset += *pKernel.PeginAmount
					*pKernel.PeginAmount = 0
				} else {
					*pKernel.PeginAmount += offset
					break
				}
			}
		}
	}
}

func (s *Server) PsbtSign(ctx context.Context,
	req *proto.PsbtSignRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	keychain := &mweb.Keychain{
		Scan:  (*mw.SecretKey)(req.ScanSecret),
		Spend: (*mw.SecretKey)(req.SpendSecret),
	}

	addrIndex := map[mw.PublicKey]uint32{}
	for _, pInput := range p.Inputs {
		if pInput.MwebOutputPubkey != nil && pInput.MwebAddressIndex != nil {
			addrIndex[*pInput.MwebOutputPubkey] = *pInput.MwebAddressIndex
		}
	}

	inputSigner := psbt.BasicMwebInputSigner{DeriveOutputKeys: func(
		Ko, Ke *mw.PublicKey, t *mw.SecretKey) (
		*mw.BlindingFactor, *mw.SecretKey, error) {

		if t == nil {
			sA := Ke.Mul(keychain.Scan)
			t = (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))
		}

		htOutKey := (*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:]))
		B_i := Ko.Div(htOutKey)
		addr := &mw.StealthAddress{Scan: B_i.Mul(keychain.Scan), Spend: B_i}
		if !addr.Equal(keychain.Address(addrIndex[*Ko])) {
			return nil, nil, errors.New("address mismatch")
		}

		return (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, t[:])),
			keychain.SpendKey(addrIndex[*Ko]).Mul(htOutKey), nil
	}}

	signer, err := psbt.NewSigner(p, inputSigner)
	if err != nil {
		return nil, err
	}

	if _, err = signer.SignMwebComponents(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err = p.Serialize(&buf); err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{RawPsbt: buf.Bytes()}, nil
}

func (s *Server) PsbtExtract(ctx context.Context,
	req *proto.PsbtExtractRequest) (*proto.CreateResponse, error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.RawPsbt), false)
	if err != nil {
		return nil, err
	}

	tx, err := psbt.Extract(p)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
		return nil, err
	}

	outputId := map[mw.Commitment]*chainhash.Hash{}
	for _, output := range tx.Mweb.TxBody.Outputs {
		outputId[output.Commitment] = output.Hash()
	}

	resp := &proto.CreateResponse{RawTx: buf.Bytes()}
	for _, pOutput := range p.Outputs {
		if pOutput.OutputCommit != nil {
			resp.OutputId = append(resp.OutputId,
				hex.EncodeToString(outputId[*pOutput.OutputCommit][:]))
		}
	}

	return resp, nil
}
