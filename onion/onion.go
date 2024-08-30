package onion

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"golang.org/x/crypto/chacha20"
	"lukechampine.com/blake3"
)

type (
	Hop struct {
		PubKey       *ecdh.PublicKey
		KernelBlind  mw.BlindingFactor
		StealthBlind mw.BlindingFactor
		Fee          uint64
		Output       *wire.MwebOutput
	}
	Onion struct {
		Input struct {
			OutputId     hexBytes `json:"output_id"`
			Commitment   hexBytes `json:"output_commit"`
			OutputPubKey hexBytes `json:"output_pk"`
			InputPubKey  hexBytes `json:"input_pk"`
			Signature    hexBytes `json:"input_sig"`
		} `json:"input"`
		Payloads   hexBytes `json:"enc_payloads"`
		PubKey     hexBytes `json:"ephemeral_xpub"`
		OwnerProof hexBytes `json:"owner_proof"`
	}
	hexBytes []byte
)

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func New(hops []*Hop) (*Onion, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	onion := &Onion{PubKey: privKey.PublicKey().Bytes()}

	var secrets, payloads [][]byte
	for i, hop := range hops {
		secret, err := privKey.ECDH(hop.PubKey)
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

		buf.Write(hop.KernelBlind[:])
		buf.Write(hop.StealthBlind[:])
		binary.Write(&buf, binary.BigEndian, hop.Fee)

		if hop.Output != nil {
			buf.WriteByte(1)
			hop.Output.Serialize(&buf)
		} else {
			buf.WriteByte(0)
		}

		payloads = append(payloads, buf.Bytes())
	}

	for i := len(payloads) - 1; i >= 0; i-- {
		cipher := newCipher(secrets[i])
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

func newCipher(secret []byte) *chacha20.Cipher {
	h := hmac.New(sha256.New, []byte("MWIXNET"))
	h.Write(secret)
	cipher, _ := chacha20.NewUnauthenticatedCipher(h.Sum(nil), []byte("NONCE1234567"))
	return cipher
}

func (onion *Onion) Sign(input *wire.MwebInput, spendKey *mw.SecretKey) {
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

func (onion *Onion) Peel(privKey *ecdh.PrivateKey) (*Hop, *Onion, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(onion.PubKey)
	if err != nil {
		return nil, nil, err
	}
	secret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, nil, err
	}
	cipher := newCipher(secret)

	var (
		count, size uint64
		payload     []byte
		payloads    bytes.Buffer
	)
	r := bytes.NewReader(onion.Payloads)
	if err = binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, nil, err
	}
	binary.Write(&payloads, binary.BigEndian, count-1)
	for i := uint64(0); i < count; i++ {
		if err = binary.Read(r, binary.BigEndian, &size); err != nil {
			return nil, nil, err
		}
		buf := make([]byte, size)
		if _, err = r.Read(buf); err != nil {
			return nil, nil, err
		}
		cipher.XORKeyStream(buf, buf)
		if i == 0 {
			payload = buf
		} else {
			binary.Write(&payloads, binary.BigEndian, size)
			payloads.Write(buf)
		}
	}

	r = bytes.NewReader(payload)
	ver, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	if ver != 0 {
		return nil, nil, errors.New("wrong onion version")
	}

	onion = &Onion{
		Payloads: payloads.Bytes(),
		PubKey:   make([]byte, 32),
	}
	if _, err = r.Read(onion.PubKey); err != nil {
		return nil, nil, err
	}

	hop := &Hop{}
	if _, err = r.Read(hop.KernelBlind[:]); err != nil {
		return nil, nil, err
	}
	if _, err = r.Read(hop.StealthBlind[:]); err != nil {
		return nil, nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &hop.Fee); err != nil {
		return nil, nil, err
	}

	hasOutput, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	if hasOutput == 1 {
		hop.Output = &wire.MwebOutput{}
		if err = hop.Output.Deserialize(r); err != nil {
			return nil, nil, err
		}
	}

	return hop, onion, nil
}
