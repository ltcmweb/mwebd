package sign

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ltcmweb/ltcd/btcec/v2"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/hdkeychain"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/ltcutil/psbt"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
)

func Addresses(req *AddressesRequest,
	cp *chaincfg.Params) (resp AddressesResponse) {

	kc := &mweb.Keychain{
		Scan:        (*mw.SecretKey)(req.Scan),
		SpendPubKey: (*mw.PublicKey)(req.SpendPub),
	}
	for i := req.From; i < req.To; i++ {
		addr := ltcutil.NewAddressMweb(kc.Address(i), cp)
		resp.Address = append(resp.Address, addr.String())
	}
	return
}

func AddressesPubKeyHash(req *AddressesPubKeyHashRequest,
	cp *chaincfg.Params) (resp AddressesResponse, err error) {

	key, err := hdkeychain.NewKeyFromString(req.XPub)
	if err != nil {
		return
	}
	for i := req.From; i < req.To; i++ {
		key, err := key.Derive(i)
		if err != nil {
			return resp, err
		}
		a, _ := key.Address(cp)
		addr, _ := ltcutil.NewAddressWitnessPubKeyHash(a.ScriptAddress(), cp)
		resp.Address = append(resp.Address, addr.String())
	}
	return
}

func PsbtGetRecipients(req *Psbt, cp *chaincfg.Params) (
	resp PsbtGetRecipientsResponse, err error) {

	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.Psbt), false)
	if err != nil {
		return
	}

	pkScriptToAddr := func(pkScript []byte) (string, error) {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, cp)
		if err != nil {
			return "", err
		}
		var addrs2 []string
		for _, addr := range addrs {
			addrs2 = append(addrs2, addr.String())
		}
		return strings.Join(addrs2, ","), nil
	}

	for _, pInput := range p.Inputs {
		var addr string
		switch {
		case pInput.WitnessUtxo != nil:
			addr, _ = pkScriptToAddr(pInput.WitnessUtxo.PkScript)
			resp.Fee += pInput.WitnessUtxo.Value
		case pInput.MwebOutputId != nil:
			addr = hex.EncodeToString(pInput.MwebOutputId[:])
		}
		resp.InputAddress = append(resp.InputAddress, addr)
	}

	for _, pOutput := range p.Outputs {
		var addr string
		switch {
		case pOutput.StealthAddress != nil:
			addr = ltcutil.NewAddressMweb(pOutput.StealthAddress, cp).String()
		case pOutput.OutputCommit != nil:
			addr = cp.Bech32HRPMweb + "1"
		default:
			if addr, err = pkScriptToAddr(pOutput.PKScript); err != nil {
				return
			}
			resp.Fee -= int64(pOutput.Amount)
		}
		resp.Recipient = append(resp.Recipient, Recipient{
			Address: addr,
			Value:   int64(pOutput.Amount),
		})
	}

	for _, pKernel := range p.Kernels {
		for _, pegout := range pKernel.PegOuts {
			addr, err := pkScriptToAddr(pegout.PkScript)
			if err != nil {
				return resp, err
			}
			resp.Recipient = append(resp.Recipient, Recipient{
				Address: addr,
				Value:   pegout.Value,
			})
		}
		if pKernel.Fee != nil {
			resp.Fee += int64(*pKernel.Fee)
		}
		if pKernel.PeginAmount != nil {
			resp.Fee -= int64(*pKernel.PeginAmount)
		}
	}

	return
}

func PsbtSign(req *PsbtSignRequest) (resp *psbt.Packet, err error) {
	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.Psbt), false)
	if err != nil {
		return
	}

	kc := &mweb.Keychain{
		Scan:  (*mw.SecretKey)(req.Scan),
		Spend: (*mw.SecretKey)(req.Spend),
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
			sA := Ke.Mul(kc.Scan)
			t = (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))
		}

		htOutKey := (*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:]))
		B_i := Ko.Div(htOutKey)
		addr := &mw.StealthAddress{Scan: B_i.Mul(kc.Scan), Spend: B_i}
		if !addr.Equal(kc.Address(addrIndex[*Ko])) {
			return nil, nil, errors.New("address mismatch")
		}

		return (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, t[:])),
			kc.SpendKey(addrIndex[*Ko]).Mul(htOutKey), nil
	}}

	signer, err := psbt.NewSigner(p, inputSigner)
	if err != nil {
		return
	}
	if _, err = signer.SignMwebComponents(); err != nil {
		return
	}

	return p, nil
}

func PsbtSignPubKeyHash(req *PsbtSignPubKeyHashRequest) (resp *psbt.Packet, err error) {
	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.Psbt), false)
	if err != nil {
		return
	}

	tx, err := psbt.ExtractUnsignedTx(p)
	if err != nil {
		return
	}

	txInIdx := 0
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, pInput := range p.Inputs {
		if pInput.MwebOutputId == nil {
			op := wire.NewOutPoint(pInput.PrevoutHash, *pInput.PrevoutIndex)
			fetcher.AddPrevOut(*op, pInput.WitnessUtxo)
			if i < int(req.Index) {
				txInIdx++
			}
		}
	}

	txOut := p.Inputs[req.Index].WitnessUtxo
	key, pub := btcec.PrivKeyFromBytes(req.Key)
	sig, err := txscript.RawTxInWitnessSignature(tx,
		txscript.NewTxSigHashes(tx, fetcher), txInIdx,
		txOut.Value, txOut.PkScript, txscript.SigHashAll, key)
	if err != nil {
		return
	}

	u := psbt.Updater{Upsbt: p}
	_, err = u.Sign(int(req.Index), sig, pub.SerializeCompressed(), nil, nil)
	if err != nil {
		return
	}
	if err = psbt.Finalize(p, int(req.Index)); err != nil {
		return
	}

	return p, nil
}

func PsbtFinalize(req *Psbt) (resp *psbt.Packet, err error) {
	p, err := psbt.NewFromRawBytes(bytes.NewReader(req.Psbt), false)
	if err != nil {
		return
	}
	if err = psbt.MaybeFinalizeAll(p); err != nil {
		return
	}

	return p, nil
}
