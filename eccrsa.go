package eccrsa

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"

	//"github.com/gonum/mathext/prng"
	"gonum.org/v1/gonum/mathext/prng"
)

type Random struct {
	r []*prng.MT19937_64
	i int
	b []byte
}

func (r *Random) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		if len(r.b) == 0 {
			u := r.r[r.i].Uint64()
			r.b = make([]byte, 8)
			binary.BigEndian.PutUint64(r.b, u)
			r.i++
			if r.i == len(r.r) {
				r.i = 0
			}
		}
		p[i] = r.b[0]
		r.b = r.b[1:]
	}
	return len(p), nil
}

func DeriveKey(k *ecdsa.PrivateKey, n int) (*rsa.PrivateKey, error) {
	b := k.D.Bytes()
	for len(b) < 32 {
		b = append([]byte{0}, b...)
	}
	b1 := b[0:8]
	b2 := b[8:16]
	b3 := b[16:24]
	b4 := b[24:32]
	s1 := binary.BigEndian.Uint64(b1)
	s2 := binary.BigEndian.Uint64(b2)
	s3 := binary.BigEndian.Uint64(b3)
	s4 := binary.BigEndian.Uint64(b4)

	r1 := prng.NewMT19937_64()
	r1.Seed(s1)
	r2 := prng.NewMT19937_64()
	r2.Seed(s2)
	r3 := prng.NewMT19937_64()
	r3.Seed(s3)
	r4 := prng.NewMT19937_64()
	r4.Seed(s4)

	reader := &Random{r: []*prng.MT19937_64{r1, r2, r3, r4}}
	return rsa.GenerateKey(reader, n)
}
