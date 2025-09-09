package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	"github.com/ltcmweb/ltcd/btcec/v2"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/ltcutil/psbt"
	"github.com/ltcmweb/ltcd/txscript"
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
	for i, txIn := range tx.TxIn {
		txOut := req.WitnessUtxo[i]
		p.Inputs = append(p.Inputs, psbt.PInput{
			WitnessUtxo:  wire.NewTxOut(txOut.Value, txOut.PkScript),
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

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
}

func (s *Server) PsbtAddInput(ctx context.Context,
	req *proto.PsbtAddInputRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
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

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
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

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
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

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
}

func (s *Server) PsbtAddPegout(ctx context.Context,
	req *proto.PsbtAddPegoutRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
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

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
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
		for i, pKernel := range p.Kernels {
			if pKernel.Signature == nil && pKernel.PeginAmount != nil {
				if *pKernel.PeginAmount <= -offset {
					offset += *pKernel.PeginAmount
					p.Kernels[i].PeginAmount = nil
				} else {
					*pKernel.PeginAmount += offset
					break
				}
			}
		}
	}
}

func (s *Server) PsbtGetRecipients(ctx context.Context,
	req *proto.PsbtGetRecipientsRequest) (*proto.PsbtGetRecipientsResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
	if err != nil {
		return nil, err
	}

	var addr ltcutil.Address
	chainParams := s.cs.ChainParams()
	resp := &proto.PsbtGetRecipientsResponse{}

	pkScriptToAddr := func(pkScript []byte) (ltcutil.Address, error) {
		_, addr, n, err := txscript.ExtractPkScriptAddrs(pkScript, &chainParams)
		if err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, errors.New("pkscript doesn't encode just one address")
		}
		return addr[0], nil
	}

	for _, pInput := range p.Inputs {
		switch {
		case pInput.WitnessUtxo != nil:
			resp.Fee += pInput.WitnessUtxo.Value
		case pInput.MwebAmount != nil:
			resp.Fee += int64(*pInput.MwebAmount)
		}
	}

	for _, pOutput := range p.Outputs {
		if pOutput.StealthAddress != nil {
			addr = ltcutil.NewAddressMweb(pOutput.StealthAddress, &chainParams)
		} else {
			if addr, err = pkScriptToAddr(pOutput.PKScript); err != nil {
				return nil, err
			}
		}
		resp.Recipient = append(resp.Recipient, &proto.PsbtRecipient{
			Address: addr.String(),
			Value:   int64(pOutput.Amount),
		})
		resp.Fee -= int64(pOutput.Amount)
	}

	for _, pKernel := range p.Kernels {
		for _, pegout := range pKernel.PegOuts {
			if addr, err = pkScriptToAddr(pegout.PkScript); err != nil {
				return nil, err
			}
			resp.Recipient = append(resp.Recipient, &proto.PsbtRecipient{
				Address: addr.String(),
				Value:   pegout.Value,
			})
			resp.Fee -= pegout.Value
		}
	}

	return resp, nil
}

func (s *Server) PsbtSign(ctx context.Context,
	req *proto.PsbtSignRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
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

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
}

func (s *Server) PsbtSignNonMweb(ctx context.Context,
	req *proto.PsbtSignNonMwebRequest) (*proto.PsbtResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
	if err != nil {
		return nil, err
	}

	tx, err := psbt.ExtractUnsignedTx(p)
	if err != nil {
		return nil, err
	}

	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for _, pInput := range p.Inputs {
		if pInput.MwebOutputId == nil {
			op := wire.NewOutPoint(pInput.PrevoutHash, *pInput.PrevoutIndex)
			fetcher.AddPrevOut(*op, pInput.WitnessUtxo)
		}
	}

	txOut := p.Inputs[req.Index].WitnessUtxo
	key, pub := btcec.PrivKeyFromBytes(req.PrivKey)
	sig, err := txscript.RawTxInWitnessSignature(tx,
		txscript.NewTxSigHashes(tx, fetcher), int(req.Index),
		txOut.Value, txOut.PkScript, txscript.SigHashAll, key)
	if err != nil {
		return nil, err
	}

	u := psbt.Updater{Upsbt: p}
	_, err = u.Sign(int(req.Index), sig, pub.SerializeCompressed(), nil, nil)
	if err != nil {
		return nil, err
	}
	if err = psbt.Finalize(p, int(req.Index)); err != nil {
		return nil, err
	}

	b64, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return &proto.PsbtResponse{PsbtB64: b64}, nil
}

func (s *Server) PsbtExtract(ctx context.Context,
	req *proto.PsbtExtractRequest) (*proto.CreateResponse, error) {

	p, err := psbt.NewFromRawBytes(strings.NewReader(req.PsbtB64), true)
	if err != nil {
		return nil, err
	}

	var tx *wire.MsgTx
	if req.Unsigned {
		tx, err = psbt.ExtractUnsignedTx(p)
	} else {
		tx, err = psbt.Extract(p)
	}
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
		return nil, err
	}

	outputId := map[mw.Commitment]chainhash.Hash{}
	if tx.Mweb != nil {
		for _, output := range tx.Mweb.TxBody.Outputs {
			outputId[output.Commitment] = *output.Hash()
		}
	}

	resp := &proto.CreateResponse{RawTx: buf.Bytes()}
	for _, pOutput := range p.Outputs {
		if pOutput.OutputCommit != nil {
			outputId := outputId[*pOutput.OutputCommit]
			resp.OutputId = append(resp.OutputId,
				hex.EncodeToString(outputId[:]))
		}
	}

	return resp, nil
}
