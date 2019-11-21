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

	"crypto/sha256"
	"strconv"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
)

// DMCFEClient is to be instantiated by the client. Idx presents index of the client.
type DMCFEClient struct {
	Idx          int
	ClientSecKey *big.Int
	ClientPubKey *bn256.G1
	Share        data.Matrix
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

// SetShare sets a shared key for client c, based on the public keys of all the
// clients involved in the scheme. It assumes that Idx of a client indicates
// which is the corresponding public key in pubKeys. Shared keys are such that
// each client has a random key but all the shared keys sum to 0.
func (c *DMCFEClient) SetShare(pubKeys []*bn256.G1) error {
	c.Share = data.NewConstantMatrix(2, 2, big.NewInt(0))
	var add data.Matrix
	var err error
	for k := 0; k < len(pubKeys); k++ {
		if k == c.Idx {
			continue
		}
		sharedG1 := new(bn256.G1).ScalarMult(pubKeys[k], c.ClientSecKey)
		sharedKey := sha256.Sum256([]byte(sharedG1.String()))

		add, err = data.NewRandomDetMatrix(2, 2, bn256.Order, &sharedKey)
		if err != nil {
			return err
		}

		if k < c.Idx {
			c.Share, err = c.Share.Add(add)
			if err != nil {
				return err
			}
		} else {
			c.Share, err = c.Share.Sub(add)
			if err != nil {
				return err
			}

		}
		c.Share = c.Share.Mod(bn256.Order)
	}

	return nil
}

// Encrypt encrypts number x under some label.
func (c *DMCFEClient) Encrypt(x *big.Int, label string) (*bn256.G1, error) {

	cipher := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < 2; i++ {
		hs, err := bn256.HashG1(strconv.Itoa(i) + " " + label)
		if err != nil {
			return nil, err
		}
		hs.ScalarMult(hs, c.S[i])
		cipher.Add(cipher, hs)
	}

	pow := new(big.Int).Set(x)
	gx := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	if pow.Sign() < 0 {
		pow.Neg(pow)
		gx.Neg(gx)
	}
	gx.ScalarMult(gx, pow)
	cipher.Add(cipher, gx)

	return cipher, nil
}

// DeriveKeyShare generates client's key share. Decryptor needs shares from all clients.
func (c *DMCFEClient) DeriveKeyShare(y data.Vector) (data.VectorG2, error) {
	hs := make([]*bn256.G2, 2)
	var err error
	for i := 0; i < 2; i++ {
		hs[i], err = bn256.HashG2(strconv.Itoa(i) + " " + y.String())
		if err != nil {
			return nil, err
		}
	}

	keyShare := data.VectorG2{new(bn256.G2).ScalarBaseMult(big.NewInt(0)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(0))}
	for k := 0; k < 2; k++ {
		for i := 0; i < 2; i++ {
			add := new(bn256.G2).ScalarMult(hs[i], c.Share[k][i])
			keyShare[k].Add(keyShare[k], add)
		}

		pow := new(big.Int).Mul(y[c.Idx], c.S[k])
		pow.Mod(pow, bn256.Order)
		gS := new(bn256.G2).ScalarBaseMult(pow)
		keyShare[k].Add(keyShare[k], gS)
	}

	return keyShare, nil
}

// DMCFEDecrypt is to be called by a party that wants to decrypt a message - to compute inner product
// of x and y. It needs ciphertexts from all clients and key shares from all clients. The label is
// a string under which vector x has been encrypted (each client encrypted x_i under this label). The value bound
// specifies the bound of the output (solution will be in the interval (-bound, bound)) and can be nil.
func DMCFEDecrypt(ciphers []*bn256.G1, keyShares []data.VectorG2, y data.Vector, label string,
	bound *big.Int) (*big.Int, error) {
	key1 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	key2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(keyShares); i++ {
		key1.Add(key1, keyShares[i][0])
		key2.Add(key2, keyShares[i][1])
	}

	gen2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	cSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	cAdd := new(bn256.G1)
	pow := new(big.Int)
	for i := 0; i < len(ciphers); i++ {
		cAdd.Set(ciphers[i])
		pow.Set(y[i])
		if pow.Sign() < 0 {
			cAdd.Neg(cAdd)
			pow.Neg(pow)
		}

		cAdd.ScalarMult(cAdd, pow)
		cSum.Add(cSum, cAdd)
	}
	s := bn256.Pair(cSum, gen2)

	hs := make([]*bn256.G1, 2)
	var err error
	for i := 0; i < 2; i++ {
		hs[i], err = bn256.HashG1(strconv.Itoa(i) + " " + label)
		if err != nil {
			return nil, err
		}
	}

	t1 := bn256.Pair(hs[0], key1)
	t2 := bn256.Pair(hs[1], key2)
	t1.Add(t1, t2)
	t1.Neg(t1)
	s.Add(s, t1)

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(s, g)

	return dec, err
}
