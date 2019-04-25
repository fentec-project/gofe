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

// DDHParams represents configuration parameters for the DDH scheme instance.
type DDHParams struct {
	// length of input vectors x and y
	L     int
	// The value by which coordinates of input vectors x and y are bounded.
	Bound *big.Int
	// Generator of a cyclic group Z_P: G^(Q) = 1 (mod P).
	G     *big.Int
	// Modulus - we are operating in a cyclic group Z_P.
	P     *big.Int
	// Order of the generator G.
	Q     *big.Int
}

// DDH represents a scheme instantiated from the DDH assumption,
// based on the DDH variant by
// Abdalla, Bourse, De Caro, and Pointchev:
// "Simple Functional Encryption Schemes for Inner Products".
type DDH struct {
	Params *DDHParams
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
		Params: &DDHParams{
			L:     l,
			Bound: bound,
			G:     key.G,
			P:     key.P,
			Q:     key.Q,
		},
	}

	return &sip, nil
}

// NewDDHFromParams takes configuration parameters of an existing
// DDH scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new DDH instance.
func NewDDHFromParams(params *DDHParams) *DDH {
	return &DDH{
		Params: params,
	}
}

// GenerateMasterKeys generates a pair of master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *DDH) GenerateMasterKeys() (data.Vector, data.Vector, error) {
	masterSecKey := make(data.Vector, d.Params.L)
	masterPubKey := make(data.Vector, d.Params.L)

	for i := 0; i < d.Params.L; i++ {
		x, err := emmy.GetRandomIntFromRange(big.NewInt(2), d.Params.Q)
		if err != nil {
			return nil, nil, err
		}
		y := internal.ModExp(d.Params.G, x, d.Params.P)
		masterSecKey[i] = x
		masterPubKey[i] = y
	}

	return masterSecKey, masterPubKey, nil
}

// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *DDH) DeriveKey(masterSecKey, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	key, err := masterSecKey.Dot(y)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(key, d.Params.Q), nil
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *DDH) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	r, err := emmy.GetRandomIntFromRange(big.NewInt(1), d.Params.P)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]*big.Int, len(x)+1)
	// ct0 = g^r
	ct0 := new(big.Int).Exp(d.Params.G, r, d.Params.P)
	ciphertext[0] = ct0

	for i := 0; i < len(x); i++ {
		// ct_i = h_i^r * g^x_i
		// ct_i = mpk[i]^r * g^x_i
		t1 := new(big.Int).Exp(masterPubKey[i], r, d.Params.P)
		t2 := internal.ModExp(d.Params.G, x[i], d.Params.P)
		ct := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.P)
		ciphertext[i+1] = ct
	}

	return ciphertext, nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *DDH) Decrypt(cipher data.Vector, key *big.Int, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	num := big.NewInt(1)
	for i, ct := range cipher[1:] {
		t1 := internal.ModExp(ct, y[i], d.Params.P)
		num = num.Mod(new(big.Int).Mul(num, t1), d.Params.P)
	}

	denom := internal.ModExp(cipher[0], key, d.Params.P)
	denomInv := new(big.Int).ModInverse(denom, d.Params.P)
	r := new(big.Int).Mod(new(big.Int).Mul(num, denomInv), d.Params.P)

	bound := new(big.Int).Mul(big.NewInt(int64(d.Params.L)), new(big.Int).Exp(d.Params.Bound, big.NewInt(2), big.NewInt(0)))

	calc, err := dlog.NewCalc().InZp(d.Params.P, d.Params.Q)
	if err != nil {
		return nil, err
	}
	calc = calc.WithNeg()

	res, err := calc.WithBound(bound).BabyStepGiantStep(r, d.Params.G)
	return res, err

}
