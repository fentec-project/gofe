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
	h1 := sha256.Sum256([]byte(label))
	h2 := sha512.Sum512([]byte(label))
	u1 := new(big.Int).SetBytes(h1[:])
	u2 := new(big.Int).SetBytes(h2[:])
	u1.Mod(u1, bn256.Order)
	u2.Mod(u2, bn256.Order)
	u := data.NewVector([]*big.Int{u1, u2})
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

	h1 := sha256.Sum256(yRepr)
	h2 := sha512.Sum512(yRepr)
	v1 := new(big.Int).SetBytes(h1[:])
	v2 := new(big.Int).SetBytes(h2[:])
	v1.Mod(v1, bn256.Order)
	v2.Mod(v2, bn256.Order)
	keyShare1 := c.s.MulScalar(y[c.Index])
	v := data.NewVector([]*big.Int{v1, v2})
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

type Decryptor struct {
	Label       string
	Ciphertexts []*bn256.G1
	KeyShares   []data.VectorG2
}

func NewDecryptor(label string, ciphertexts []*bn256.G1, keyShares []data.VectorG2) *Decryptor {
	return &Decryptor{
		Label:       label,
		Ciphertexts: ciphertexts,
		KeyShares:   keyShares,
	}
}
