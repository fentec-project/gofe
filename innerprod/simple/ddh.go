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

package simple

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/internal/keygen"
	emmy "github.com/xlab-si/emmy/crypto/common"
)

// ddhParams represents configuration parameters for the DDH scheme instance.
type ddhParams struct {
	// length of input vectors x and y
	l int
	// The value by which coordinates of input vectors x and y are bounded.
	bound *big.Int
	// Generator of a cyclic group Z_p: g^(p-1) = 1 (mod p).
	g *big.Int
	// Modulus - we are operating in a cyclic group Z_p.
	p *big.Int
}

// DDH represents a scheme instantiated from the DDH assumption.
type DDH struct {
	Params *ddhParams
}

// NewDDH configures a new instance of the scheme.
// It accepts the length of input vectors l, the bit length of the
// modulus (we are operating in the Z_p group), and a bound by which
// coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition l * bound² is >= order of the cyclic
// group.
func NewDDH(l, modulusLength int, bound *big.Int) (*DDH, error) {
	key, err := keygen.NewElGamal(modulusLength)
	if err != nil {
		return nil, err
	}

	if new(big.Int).Mul(big.NewInt(int64(l)), new(big.Int).Exp(bound, big.NewInt(2), big.NewInt(0))).Cmp(key.P) > 0 {
		return nil, fmt.Errorf("l * bound^2 should be smaller than group order")
	}

	sip := DDH{
		Params: &ddhParams{
			l:     l,
			bound: bound,
			g:     key.G,
			p:     key.P,
		},
	}

	return &sip, nil
}

// NewDDHFromParams takes configuration parameters of an existing
// DDH scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new DDH instance.
func NewDDHFromParams(params *ddhParams) *DDH {
	return &DDH{
		Params: params,
	}
}

// GenerateMasterKeys generates a pair of master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *DDH) GenerateMasterKeys() (data.Vector, data.Vector, error) {
	masterSecKey := make(data.Vector, d.Params.l)
	masterPubKey := make(data.Vector, d.Params.l)

	for i := 0; i < d.Params.l; i++ {
		x, err := emmy.GetRandomIntFromRange(big.NewInt(2), new(big.Int).Sub(d.Params.p, big.NewInt(1)))
		if err != nil {
			return nil, nil, err
		}
		y := internal.ModExp(d.Params.g, x, d.Params.p)
		masterSecKey[i] = x
		masterPubKey[i] = y
	}

	return masterSecKey, masterPubKey, nil
}

// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *DDH) DeriveKey(masterSecKey, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	key, err := masterSecKey.Dot(y)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(key, new(big.Int).Sub(d.Params.p, big.NewInt(1))), nil
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *DDH) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	r, err := emmy.GetRandomIntFromRange(big.NewInt(1), d.Params.p)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]*big.Int, len(x)+1)
	// ct0 = g^r
	ct0 := new(big.Int).Exp(d.Params.g, r, d.Params.p)
	ciphertext[0] = ct0

	for i := 0; i < len(x); i++ {
		// ct_i = h_i^r * g^x_i
		// ct_i = mpk[i]^r * g^x_i
		t1 := new(big.Int).Exp(masterPubKey[i], r, d.Params.p)
		t2 := internal.ModExp(d.Params.g, x[i], d.Params.p)
		ct := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.p)
		ciphertext[i+1] = ct
	}

	return ciphertext, nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *DDH) Decrypt(cipher data.Vector, key *big.Int, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	num := big.NewInt(1)
	for i, ct := range cipher[1:] {
		t1 := internal.ModExp(ct, y[i], d.Params.p)
		num = num.Mod(new(big.Int).Mul(num, t1), d.Params.p)
	}

	denom := internal.ModExp(cipher[0], key, d.Params.p)
	denomInv := new(big.Int).ModInverse(denom, d.Params.p)
	r := new(big.Int).Mod(new(big.Int).Mul(num, denomInv), d.Params.p)

	order := new(big.Int).Sub(d.Params.p, big.NewInt(1))
	bound := new(big.Int).Mul(big.NewInt(int64(d.Params.l)), new(big.Int).Exp(d.Params.bound, big.NewInt(2), big.NewInt(0)))

	calc, err := dlog.NewCalc().InZp(d.Params.p, order)
	if err != nil {
		return nil, err
	}
	calc = calc.WithNeg()

	res, err := calc.WithBound(bound).BabyStepGiantStep(r, d.Params.g)
	return res, err

}
