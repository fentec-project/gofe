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

package decentralized

import (
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"

	"crypto/sha256"
	"crypto/sha512"
)

type Client struct {
	Index int
	T     data.Matrix
	s     data.Vector
}

func NewClient(index int, T data.Matrix) (*Client, error) {
	sampler := sample.NewUniform(bn256.Order)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, fmt.Errorf("could not generate random vector")
	}

	return &Client{
		Index: index,
		T:     T,
		s:     s,
	}, nil
}

func (c *Client) Encrypt(x *big.Int, label string) (*bn256.G1, error) {
	u := hash([]byte(label))
	ct, err := u.Dot(c.s)
	if err != nil {
		return nil, fmt.Errorf("error when computing inner product: %v", err)
	}
	ct.Add(ct, x)
	ct.Mod(ct, bn256.Order)

	return new(bn256.G1).ScalarBaseMult(ct), nil
}

func (c *Client) GenerateKeyShare(y data.Vector) (data.VectorG2, error) {
	var yRepr []byte
	for i := 0; i < len(y); i++ {
		yRepr = append(yRepr, y[i].Bytes()...)
	}
	v := hash(yRepr)

	keyShare1 := c.s.MulScalar(y[c.Index])
	keyShare2, err := c.T.MulVec(v)
	if err != nil {
		return nil, fmt.Errorf("error when multiplying matrix with vector: %v", err)
	}

	keyShare := keyShare1.Add(keyShare2)
	keyShare.Mod(bn256.Order)
	k1 := new(bn256.G2).ScalarBaseMult(keyShare[0])
	k2 := new(bn256.G2).ScalarBaseMult(keyShare[1])

	return data.VectorG2{k1, k2}, nil
}

func hash(bytes []byte) data.Vector {
	h1 := sha256.Sum256(bytes)
	h2 := sha512.Sum512(bytes)
	u1 := new(big.Int).SetBytes(h1[:])
	u2 := new(big.Int).SetBytes(h2[:])
	u1.Mod(u1, bn256.Order)
	u2.Mod(u2, bn256.Order)
	u := data.NewVector([]*big.Int{u1, u2})

	return u
}

type Decryptor struct {
	y           data.Vector
	label       string
	ciphertexts []*bn256.G1
	key1        *bn256.G2
	key2        *bn256.G2
}

func NewDecryptor(y data.Vector, label string, ciphertexts []*bn256.G1, keyShares []data.VectorG2) *Decryptor {
	key1 := keyShares[0][0]
	key2 := keyShares[0][1]
	for i := 1; i < len(keyShares); i++ {
		key1.Add(key1, keyShares[i][0])
		key2.Add(key2, keyShares[i][0])
	}
	return &Decryptor{
		y:           y,
		label:       label,
		ciphertexts: ciphertexts,
		key1:        key1,
		key2:        key2,
	}
}

func (d *Decryptor) Decrypt() *bn256.GT {
	y0 := new(bn256.G2).ScalarBaseMult(d.y[0])
	s := bn256.Pair(d.ciphertexts[0], y0)
	for i := 1; i < len(d.ciphertexts); i++ {
		yi := new(bn256.G2).ScalarBaseMult(d.y[i])
		p := bn256.Pair(d.ciphertexts[i], yi)
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

	// TODO: discrete log

	return s
}
