package abe

import (
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"github.com/cloudflare/bn256"
)

type abeParams struct {
	l     int   // number of attributes
	p     *big.Int  // order of the elliptic curve
}

type Abe struct {
	Params *abeParams
}

func newAbe(l int) (*Abe){
	return &Abe{Params: &abeParams{
		l:	l,
		p:  bn256.Order,
	}}
}

type AbePubKey struct {
	t data.VectorG2
	y *bn256.GT
}

// should we put public key into Abe struct
func (a Abe) GenerateMasterKeys() (*AbePubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.p)
	sk, err := data.NewRandomVector(a.Params.l + 1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk.MulG2()
	y := bn256.Pair(new(bn256.G1), new(bn256.G2)) // is this the same as new(bn256.GT)?
	return &AbePubKey{t: t, y: y,}, sk, nil
}

type AbeCipher struct {
	gamma []int
	e0 *bn256.GT
	e data.VectorG2
}

func (a Abe) Encrypt(msg *bn256.GT, gamma []int, pk *AbePubKey) (*AbeCipher, error) {
	sampler := sample.NewUniform(a.Params.p)
	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}
	e0 := new(bn256.GT).Add(msg, new(bn256.GT).ScalarMult(pk.y, s))
	e := make(data.VectorG2, len(gamma))
	for  i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.t[el], s)
	}

	return &AbeCipher{gamma: gamma, e0: e0, e: e,}, nil
}

func (a Abe) KeyGen(msp data.Matrix, msk data.Vector, mpk AbePubKey) (data.VectorG1) {

}