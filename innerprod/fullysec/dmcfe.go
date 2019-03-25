/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fullysec

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"

	"crypto/sha256"
	"crypto/sha512"
)

// DMCFEClient is to be instantiated by the encryptor. Idx presents index of the encryptor entity.
type DMCFEClient struct {
	Idx int
	t   data.Matrix
	s   data.Vector
}

// NewDMCFEClient is to be called by the party that wants to encrypt number x_i.
// The decryptor will be able to compute inner product of x and y where x = (x_1,...,x_l) and
// y is publicly known vector y = (y_1,...,y_l).
// Value idx presents index of the party and matrix t is part of the client secret key.
// Matrix t needs to be generated interactively with other clients but nobody except the client
// should know its value (by secure multi-party computation).
func NewDMCFEClient(idx int, t data.Matrix) (*DMCFEClient, error) {
	sampler := sample.NewUniform(bn256.Order)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, fmt.Errorf("could not generate random vector")
	}

	return &DMCFEClient{
		Idx: idx,
		t:   t,
		s:   s,
	}, nil
}

// Encrypt encrypts number x under some label.
func (c *DMCFEClient) Encrypt(x *big.Int, label string) (*bn256.G1, error) {
	u := hash([]byte(label))
	ct, err := u.Dot(c.s)
	if err != nil {
		return nil, errors.Wrap(err, "error computing inner product")
	}
	ct.Add(ct, x)
	ct.Mod(ct, bn256.Order)

	return new(bn256.G1).ScalarBaseMult(ct), nil
}

// GenerateKeyShare generates client's key share. Decryptor needs shares from all clients.
func (c *DMCFEClient) GenerateKeyShare(y data.Vector) (data.VectorG2, error) {
	yReprCap := 0
	for _, yi := range y {
		yReprCap += len(yi.Bytes())
	}
	yReprCap += len(y)

	yRepr := make([]byte, 0, yReprCap)
	for _, yi := range y {
		yRepr = append(yRepr, yi.Bytes()...)
		if yi.Sign() == 1 {
			yRepr = append(yRepr, 1)
		} else {
			yRepr = append(yRepr, 2)
		}
	}
	v := hash(yRepr)

	keyShare1 := c.s.MulScalar(y[c.Idx])
	keyShare2, err := c.t.MulVec(v)
	if err != nil {
		return nil, errors.Wrap(err, "error multiplying matrix with vector")
	}

	keyShare := keyShare1.Add(keyShare2)
	keyShare = keyShare.Mod(bn256.Order)
	k1 := new(bn256.G2).ScalarBaseMult(keyShare[0])
	k2 := new(bn256.G2).ScalarBaseMult(keyShare[1])

	return data.VectorG2{k1, k2}, nil
}

type DMCFEDecryptor struct {
	y        data.Vector
	label    string
	ciphers  []*bn256.G1
	key1     *bn256.G2
	key2     *bn256.G2
	bound    *big.Int
	gCalc    *dlog.CalcBN256
	gInvCalc *dlog.CalcBN256
}

// NewDMCFEDecryptor is to be called by a party that wants to decrypt a message - to compute inner product
// of x and y. It needs ciphertexts from all clients and key shares from all clients. The label is
// a string under which vector x has been encrypted (each client encrypted x_i under this label). The value bound
// specifies the bound of vector coordinates.
func NewDMCFEDecryptor(y data.Vector, label string, ciphers []*bn256.G1, keyShares []data.VectorG2,
	bound *big.Int) *DMCFEDecryptor {
	key1 := keyShares[0][0]
	key2 := keyShares[0][1]
	for i := 1; i < len(keyShares); i++ {
		key1.Add(key1, keyShares[i][0])
		key2.Add(key2, keyShares[i][1])
	}

	return &DMCFEDecryptor{
		y:        y,
		label:    label,
		ciphers:  ciphers,
		key1:     key1,
		key2:     key2,
		bound:    bound,
		gCalc:    dlog.NewCalc().InBN256(),
		gInvCalc: dlog.NewCalc().InBN256(),
	}
}

func (d *DMCFEDecryptor) Decrypt() (*big.Int, error) {
	y0 := new(bn256.G2).ScalarBaseMult(d.y[0])
	s := bn256.Pair(d.ciphers[0], y0)
	for i := 1; i < len(d.ciphers); i++ {
		yi := new(bn256.G2).ScalarBaseMult(d.y[i])
		p := bn256.Pair(d.ciphers[i], yi)
		s.Add(s, p)
	}

	u := hash([]byte(d.label))
	u0 := new(bn256.G1).ScalarBaseMult(u[0])
	u1 := new(bn256.G1).ScalarBaseMult(u[1])
	t1 := bn256.Pair(u0, d.key1)
	t2 := bn256.Pair(u1, d.key2)
	t1.Add(t1, t2)
	t1.Neg(t1)
	s.Add(s, t1)

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)

	var dec *big.Int // dec is decryption
	dec, err := d.gCalc.WithBound(d.bound).BabyStepGiantStep(s, g)
	if err != nil {
		gInv := new(bn256.GT).Neg(g)
		dec, err = d.gInvCalc.WithBound(d.bound).BabyStepGiantStep(s, gInv)
		if err != nil {
			return nil, err
		}
		dec.Neg(dec)
	}

	return dec, nil
}

func hash(bytes []byte) data.Vector {
	h1 := sha256.Sum256(bytes)
	h2 := sha512.Sum512(bytes)
	u1 := new(big.Int).SetBytes(h1[:])
	u2 := new(big.Int).SetBytes(h2[:])
	u1.Mod(u1, bn256.Order)
	u2.Mod(u2, bn256.Order)

	return data.NewVector([]*big.Int{u1, u2})
}
