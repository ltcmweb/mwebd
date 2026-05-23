package sign

import (
	"encoding/binary"
	"io"
	"unsafe"
)

func get(r io.Reader, vals ...any) (err error) {
	for _, v := range vals {
		switch v := v.(type) {
		case *[]byte:
			err = getBytes(r, v)
		case *string:
			err = getString(r, v)
		case *[]string:
			err = getStrings(r, v)
		default:
			err = binary.Read(r, binary.LittleEndian, v)
		}
		if err != nil {
			return
		}
	}
	return
}

func getBytes(r io.Reader, bs *[]byte) (err error) {
	var n uint32
	if err = get(r, &n); err != nil {
		return
	}
	*bs = make([]byte, n)
	_, err = io.ReadFull(r, *bs)
	return
}

func getString(r io.Reader, s *string) (err error) {
	var bs []byte
	err = get(r, &bs)
	*s = unsafe.String(unsafe.SliceData(bs), len(bs))
	return
}

func getStrings(r io.Reader, ss *[]string) (err error) {
	var n uint32
	if err = get(r, &n); err != nil {
		return
	}
	*ss = make([]string, n)
	for i := range n {
		if err = get(r, &(*ss)[i]); err != nil {
			return
		}
	}
	return
}
