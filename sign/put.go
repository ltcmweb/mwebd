package sign

import (
	"encoding/binary"
	"io"
)

func put(w io.Writer, vals ...any) (err error) {
	for _, v := range vals {
		switch v := v.(type) {
		case []byte:
			err = putBytes(w, v)
		case string:
			err = putString(w, v)
		case []string:
			err = putStrings(w, v)
		default:
			err = binary.Write(w, binary.LittleEndian, v)
		}
		if err != nil {
			return
		}
	}
	return
}

func putBytes(w io.Writer, bs []byte) (err error) {
	if err = put(w, uint32(len(bs))); err != nil {
		return
	}
	_, err = w.Write(bs)
	return
}

func putString(w io.Writer, s string) (err error) {
	if err = put(w, uint32(len(s))); err != nil {
		return
	}
	_, err = io.WriteString(w, s)
	return
}

func putStrings(w io.Writer, ss []string) (err error) {
	if err = put(w, uint32(len(ss))); err != nil {
		return
	}
	for _, s := range ss {
		if err = put(w, s); err != nil {
			return
		}
	}
	return
}
