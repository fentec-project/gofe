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

// DMCFEClient is to be instantiated by the client. Idx presents index of the client.
type DMCFEClient struct {
	Idx          int
	ClientSecKey *big.Int
	ClientPubKey *bn256.G1
	KeyShare     data.Matrix
	S            data.Vector
}

// NewDMCFEClient is to be called by the party that wants to encrypt number x_i.
// The decryptor will be able to compute inner product of x and y where x = (x_1,...,x_l) and
// y is publicly known vector y = (y_1,...,y_l). Value idx presents index of the party, where
// it is assumed that if there are n clients, its indexes are in [0, n-1]
func NewDMCFEClient(idx int) (*DMCFEClient, error) {
	sampler := sample.NewUniform(bn256.Order)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, fmt.Errorf("could not generate random vector")
	}
	sec, err := sampler.Sample()
	if err != nil {
		return nil, fmt.Errorf("could not generate random value")
	}
	pub := new(bn256.G1).ScalarBaseMult(sec)

	return &DMCFEClient{
		Idx:          idx,
		ClientSecKey: sec,
		ClientPubKey: pub,
		S:            s,
	}, nil
}


// SetKeyShare sets a shared key for client c, based on the public keys of all the
// clients involved in the scheme. It assumes that Idx of a client indicates
// which is the corresponding public key in pubKeys. Shared keys are such that
// each client has a random key but all the shared keys sum to 0.
func (c *DMCFEClient) SetKeyShare(pubKeys []*bn256.G1) error {
	c.KeyShare = data.NewConstantMatrix(2, 2, big.NewInt(0))
	var add data.Matrix
	var err error
	for k := 0; k < len(pubKeys); k++ {
		if k == c.Idx {
			continue
		}
		sharedG1 := new(bn256.G1).ScalarMult(pubKeys[k], c.ClientSecKey)
		sharedKey := sha256.New().Sum([]byte(sharedG1.String()))
		var sharedKeyFixed [32]byte
		copy(sharedKeyFixed[:], sharedKey)

		add, err = data.NewRandomDetMatrix(2, 2, bn256.Order, &sharedKeyFixed)
		if err != nil {
			return err
		}

		if k < c.Idx {
			c.KeyShare, err = c.KeyShare.Add(add)
			if err != nil {
				return err
			}
		} else {
			c.KeyShare, err = c.KeyShare.Sub(add)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Encrypt encrypts number x under some label.
func (c *DMCFEClient) Encrypt(x *big.Int, label string) (*bn256.G1, error) {
	u := hash([]byte(label))
	ct, err := u.Dot(c.S)
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

	keyShare1 := c.S.MulScalar(y[c.Idx])
	keyShare2, err := c.KeyShare.MulVec(v)
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
	Y        data.Vector
	Label    string
	Ciphers  []*bn256.G1
	Key1     *bn256.G2
	Key2     *bn256.G2
	Bound    *big.Int
	GCalc    *dlog.CalcBN256
	GInvCalc *dlog.CalcBN256
}

// NewDMCFEDecryptor is to be called by a party that wants to decrypt a message - to compute inner product
// of x and y. It needs ciphertexts from all clients and key shares from all clients. The label is
// a string under which vector x has been encrypted (each client encrypted x_i under this label). The value bound
// specifies the bound of vector coordinates.
func NewDMCFEDecryptor(y data.Vector, label string, ciphers []*bn256.G1, keyShares []data.VectorG2,
	bound *big.Int) *DMCFEDecryptor {
	key1 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	key2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(keyShares); i++ {
		key1.Add(key1, keyShares[i][0])
		key2.Add(key2, keyShares[i][1])
	}

	return &DMCFEDecryptor{
		Y:        y,
		Label:    label,
		Ciphers:  ciphers,
		Key1:     key1,
		Key2:     key2,
		Bound:    bound,
		GCalc:    dlog.NewCalc().InBN256(),
		GInvCalc: dlog.NewCalc().InBN256(),
	}
}

func (d *DMCFEDecryptor) Decrypt() (*big.Int, error) {
	gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	cSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	cAdd := new(bn256.G1)
	pow := new(big.Int)
	for i := 0; i < len(d.Ciphers); i++ {
		cAdd.Set(d.Ciphers[i])
		pow.Set(d.Y[i])
		if pow.Sign() < 0 {
			cAdd.Neg(cAdd)
			pow.Neg(pow)
		}

		cAdd.ScalarMult(cAdd, pow)
		cSum.Add(cSum, cAdd)
	}
	s := bn256.Pair(cSum, gen)
	u := hash([]byte(d.Label))
	u0 := new(bn256.G1).ScalarBaseMult(u[0])
	u1 := new(bn256.G1).ScalarBaseMult(u[1])
	t1 := bn256.Pair(u0, d.Key1)
	t2 := bn256.Pair(u1, d.Key2)
	t1.Add(t1, t2)
	t1.Neg(t1)
	s.Add(s, t1)

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)

	dec, err := d.GCalc.WithNeg().WithBound(d.Bound).BabyStepGiantStep(s, g)

	return dec, err
}

// TODO: change hashing
func hash(bytes []byte) data.Vector {
	h1 := sha256.Sum256(bytes)
	h2 := sha512.Sum512(bytes)
	u1 := new(big.Int).SetBytes(h1[:])
	u2 := new(big.Int).SetBytes(h2[:])
	u1.Mod(u1, bn256.Order)
	u2.Mod(u2, bn256.Order)

	return data.NewVector([]*big.Int{u1, u2})
}
