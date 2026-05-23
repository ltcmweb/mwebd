package sign

import "io"

type Message interface {
	Serialize(io.Writer) error
	Deserialize(io.Reader) error
}

type AddressesRequest struct {
	Scan, SpendPub []byte
	From, To       uint32
}

func (m *AddressesRequest) Serialize(w io.Writer) error {
	return put(w, m.Scan, m.SpendPub, m.From, m.To)
}

func (m *AddressesRequest) Deserialize(r io.Reader) error {
	return get(r, &m.Scan, &m.SpendPub, &m.From, &m.To)
}

type AddressesPubKeyHashRequest struct {
	XPub     string
	From, To uint32
}

func (m *AddressesPubKeyHashRequest) Serialize(w io.Writer) error {
	return put(w, m.XPub, m.From, m.To)
}

func (m *AddressesPubKeyHashRequest) Deserialize(r io.Reader) error {
	return get(r, &m.XPub, &m.From, &m.To)
}

type AddressesResponse struct {
	Address []string
}

func (m *AddressesResponse) Serialize(w io.Writer) error {
	return put(w, m.Address)
}

func (m *AddressesResponse) Deserialize(r io.Reader) error {
	return get(r, &m.Address)
}

type Psbt struct {
	Psbt []byte
}

func (m *Psbt) Serialize(w io.Writer) error {
	return put(w, m.Psbt)
}

func (m *Psbt) Deserialize(r io.Reader) error {
	return get(r, &m.Psbt)
}

type Recipient struct {
	Address string
	Value   int64
}

func (m *Recipient) Serialize(w io.Writer) error {
	return put(w, m.Address, m.Value)
}

func (m *Recipient) Deserialize(r io.Reader) error {
	return get(r, &m.Address, &m.Value)
}

type PsbtGetRecipientsResponse struct {
	Recipient    []Recipient
	InputAddress []string
	Fee          int64
}

func (m *PsbtGetRecipientsResponse) Serialize(w io.Writer) (err error) {
	if err = put(w, uint32(len(m.Recipient))); err != nil {
		return
	}
	for _, recipient := range m.Recipient {
		if err = recipient.Serialize(w); err != nil {
			return
		}
	}
	return put(w, m.InputAddress, m.Fee)
}

func (m *PsbtGetRecipientsResponse) Deserialize(r io.Reader) (err error) {
	var n uint32
	if err = get(r, &n); err != nil {
		return
	}
	m.Recipient = make([]Recipient, n)
	for i := range n {
		if err = m.Recipient[i].Deserialize(r); err != nil {
			return
		}
	}
	return get(r, &m.InputAddress, &m.Fee)
}

type PsbtSignRequest struct {
	Psbt, Scan, Spend []byte
}

func (m *PsbtSignRequest) Serialize(w io.Writer) error {
	return put(w, m.Psbt, m.Scan, m.Spend)
}

func (m *PsbtSignRequest) Deserialize(r io.Reader) error {
	return get(r, &m.Psbt, &m.Scan, &m.Spend)
}

type PsbtSignPubKeyHashRequest struct {
	Psbt, Key []byte
	Index     uint32
}

func (m *PsbtSignPubKeyHashRequest) Serialize(w io.Writer) error {
	return put(w, m.Psbt, m.Key, m.Index)
}

func (m *PsbtSignPubKeyHashRequest) Deserialize(r io.Reader) error {
	return get(r, &m.Psbt, &m.Key, &m.Index)
}

type CountWriter struct{ Len int }

func (w *CountWriter) Write(p []byte) (int, error) {
	w.Len += len(p)
	return len(p), nil
}
