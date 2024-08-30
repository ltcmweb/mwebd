package mwebd

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

func TestOnion(t *testing.T) {
	const (
		totalFee  = 10
		feePerHop = 2
		inValue   = 1000
		outValue  = inValue - totalFee
	)

	var (
		randBytes = func() []byte {
			b := make([]byte, 32)
			rand.Read(b)
			return b
		}
		keychain = &mweb.Keychain{
			Scan:  (*mw.SecretKey)(randBytes()),
			Spend: (*mw.SecretKey)(randBytes()),
		}
		coin = &mweb.Coin{
			SpendKey: (*mw.SecretKey)(randBytes()),
			Blind:    (*mw.BlindingFactor)(randBytes()),
			Value:    inValue,
			OutputId: (*chainhash.Hash)(randBytes()),
		}
		recipient = &mweb.Recipient{
			Value:   outValue,
			Address: keychain.Address(0),
		}
		serverKeys []*ecdh.PrivateKey
	)

	input, output, kernelBlind, stealthBlind, err := makeCoinswapTx(coin, recipient)
	if err != nil {
		t.Fatal(err)
	}

	kernelBlinds := splitBlind(kernelBlind, 5)
	stealthBlinds := splitBlind(stealthBlind, 5)

	var hops []*coinswapHop
	for i := 0; i < 5; i++ {
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverKeys = append(serverKeys, privKey)
		hops = append(hops, &coinswapHop{
			pubKey:       privKey.PublicKey(),
			kernelBlind:  kernelBlinds[i],
			stealthBlind: stealthBlinds[i],
			fee:          feePerHop,
		})
	}

	onion, err := makeCoinswapOnion(hops, output)
	if err != nil {
		t.Fatal(err)
	}

	signCoinswapOnion(onion, input, coin.SpendKey)

	var (
		inputCommit   = (*mw.Commitment)(onion.Input.Commitment).PubKey()
		outputCommit  = output.Commitment.PubKey()
		inputStealth  = (*mw.PublicKey)(onion.Input.InputPubKey).Add(&output.SenderPubKey)
		outputStealth = (*mw.PublicKey)(onion.Input.OutputPubKey)
		payloads      [][]byte
		size          uint64
	)

	r := bytes.NewReader(onion.Payloads)
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	for i := size; i > 0; i-- {
		if err = binary.Read(r, binary.BigEndian, &size); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, size)
		if _, err = r.Read(payload); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}

	for i := 0; i < 5; i++ {
		pubKey, err := ecdh.X25519().NewPublicKey(onion.PubKey)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := serverKeys[i].ECDH(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		cipher := newOnionCipher(secret)
		for j := i; j < 5; j++ {
			cipher.XORKeyStream(payloads[j], payloads[j])
		}

		r := bytes.NewReader(payloads[i])
		ver, err := r.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		if ver != 0 {
			t.Fatal("wrong onion version")
		}
		if _, err = r.Read(onion.PubKey); err != nil {
			t.Fatal(err)
		}

		var kernelBlind mw.BlindingFactor
		if _, err = r.Read(kernelBlind[:]); err != nil {
			t.Fatal(err)
		}
		if kernelBlind != *hops[i].kernelBlind {
			t.Fatal("kernel blind mismatch")
		}
		excess := mw.NewCommitment(&kernelBlind, 0)
		inputCommit = inputCommit.Add(excess.PubKey())

		var stealthBlind mw.SecretKey
		if _, err = r.Read(stealthBlind[:]); err != nil {
			t.Fatal(err)
		}
		if mw.BlindingFactor(stealthBlind) != *hops[i].stealthBlind {
			t.Fatal("stealth blind mismatch")
		}
		outputStealth = outputStealth.Add(stealthBlind.PubKey())

		var fee uint64
		if err = binary.Read(r, binary.BigEndian, &fee); err != nil {
			t.Fatal(err)
		}
		if fee != hops[i].fee {
			t.Fatal("fee mismatch")
		}
		excess = mw.NewCommitment(&mw.BlindingFactor{}, fee)
		outputCommit = outputCommit.Add(excess.PubKey())

		hasOutput, err := r.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		switch hasOutput {
		case 0:
			if i == 4 {
				t.Fatal("expected output")
			}
		case 1:
			if i < 4 {
				t.Fatal("unexpected output")
			}
			var output2 wire.MwebOutput
			if err = output2.Deserialize(r); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(output, &output2) {
				t.Fatal("output mismatch")
			}
		default:
			t.Fatal("bad optional byte")
		}
	}

	if *inputCommit != *outputCommit {
		t.Fatal("commitment mismatch")
	}
	if *inputStealth != *outputStealth {
		t.Fatal("stealth sums unbalanced")
	}
}
