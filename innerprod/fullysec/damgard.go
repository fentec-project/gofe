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

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/internal/keygen"
	emmy "github.com/xlab-si/emmy/crypto/common"
)

// l (int): The length of vectors to be encrypted.
// bound (int): The value by which coordinates of vectors x and y are bounded.
// g (int): Generator of a cyclic group Z_p: g**(p-1) = 1 (mod p).
// h (int): Generator of a cyclic group Z_p: h**(p-1) = 1 (mod p).
// p (int): Modulus - we are operating in a cyclic group Z_p.
type damgardParams struct {
	l     int
	bound *big.Int
	g     *big.Int
	h     *big.Int
	p     *big.Int
}

// Based on DDH variant of:
// Agrawal, Shweta, Benoit Libert, and Damien Stehle.
// "Fully secure functional encryption for inner products,
// from standard assumptions."
//
// This scheme enables encryption of vector x = [x_1, ..., x_l]; derivation of a
// key for function x -> <x,y>; and decryption which reveals
// only <x,y> and nothing else.
//
// This scheme is PUBLIC-KEY - no master secret key is needed to Encrypt the
// messages.
//
// Args:
//     l (int): The length of vectors to be encrypted.
//     bound (int): The value by which coordinates of vectors x and y are bounded.
//         That means that <x,y> < l * bound^2. Note that l * bound^2 needs to smaller
//         than group order. This makes the scheme applicable only for short
//         integer vectors.
//     modulus_length (int): Bit length of modulus p.

// Damgard represents a scheme instantiated from the DDH assumption.
type Damgard struct {
	Params *damgardParams
}

// NewDamgard configures a new instance of the scheme.
// It accepts the length of input vectors l, the bit length of the
// modulus (we are operating in the Z_p group), and a bound by which
// coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition l * bound² is >= order of the cyclic
// group.
func NewDamgard(l, modulusLength int, bound *big.Int) (*Damgard, error) {
	key, err := keygen.NewElGamal(modulusLength)
	if err != nil {
		return nil, err
	}
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)


	bSquared := new(big.Int).Exp(bound, two, nil)
	prod := new(big.Int).Mul(big.NewInt(int64(l)), bSquared)
	if prod.Cmp(key.P) > 0 {
		return nil, fmt.Errorf("l * bound^2 should be smaller than group order")
	}

	h := new(big.Int)
	for {
		r, err := emmy.GetRandomIntFromRange(one, key.P)
		if err != nil {
			return nil, err
		}
		h.Exp(key.G, r, key.P)

		// check if h is a generator of Z_p*
		if new(big.Int).Exp(h, key.Q, key.P).Cmp(one) == 0 {
			continue
		}
		if new(big.Int).Exp(h, two, key.P).Cmp(one) == 0 {
			continue
		}

		// additional checks to avoid some known attacks
		if new(big.Int).Mod(new(big.Int).Sub(key.P, one), h).Cmp(zero) == 0 {
			continue
		}
		hInv := new(big.Int).ModInverse(h, key.P)
		if new(big.Int).Mod(new(big.Int).Sub(key.P, one), hInv).Cmp(zero) == 0 {
			continue
		}
		break
	}

	return &Damgard{
		Params: &damgardParams{
			l:     l,
			bound: bound,
			g:     key.G,
			h:     h,
			p:     key.P,
		},
	}, nil
}

// NewDamgardFromParams takes configuration parameters of an existing
// Damgard scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new Damgard instance.
func NewDamgardFromParams(params *damgardParams) *Damgard {
	return &Damgard{
		Params: params,
	}
}

// DamgardSecKey is a secret key for Damgard scheme.
type DamgardSecKey struct {
	s data.Vector
	t data.Vector
}

// GenerateMasterKeys generates a master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *Damgard) GenerateMasterKeys() (*DamgardSecKey, data.Vector, error) {
	// both part of masterSecretKey
	mskS := make(data.Vector, d.Params.l)
	mskT := make(data.Vector, d.Params.l)

	masterPubKey := make([]*big.Int, d.Params.l)

	for i := 0; i < d.Params.l; i++ {
		s, err := emmy.GetRandomIntFromRange(big.NewInt(2), new(big.Int).Sub(d.Params.p, big.NewInt(1)))
		if err != nil {
			return nil, nil, err
		}
		mskS[i] = s

		t, err := emmy.GetRandomIntFromRange(big.NewInt(2), new(big.Int).Sub(d.Params.p, big.NewInt(1)))
		if err != nil {
			return nil, nil, err
		}
		mskT[i] = t

		y1 := new(big.Int).Exp(d.Params.g, s, d.Params.p)
		y2 := new(big.Int).Exp(d.Params.h, t, d.Params.p)

		masterPubKey[i] = new(big.Int).Mod(new(big.Int).Mul(y1, y2), d.Params.p)

	}

	return &DamgardSecKey{s: mskS, t: mskT}, masterPubKey, nil
}

// DamgardDerivedKey is a functional encryption key for Damgard scheme.
type DamgardDerivedKey struct {
	key1 *big.Int
	key2 *big.Int
}

// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *Damgard) DeriveKey(masterSecKey *DamgardSecKey, y data.Vector) (*DamgardDerivedKey, error) {
	if err := y.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	key1, err := masterSecKey.s.Dot(y)
	if err != nil {
		return nil, err
	}

	key2, err := masterSecKey.t.Dot(y)
	if err != nil {
		return nil, err
	}

	k1 := new(big.Int).Mod(key1, new(big.Int).Sub(d.Params.p, big.NewInt(1)))
	k2 := new(big.Int).Mod(key2, new(big.Int).Sub(d.Params.p, big.NewInt(1)))

	return &DamgardDerivedKey{key1: k1, key2: k2}, nil
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *Damgard) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	r, err := emmy.GetRandomIntFromRange(big.NewInt(1), d.Params.p)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]*big.Int, len(x)+2)
	// c = g^r
	// dd = h^r
	c := new(big.Int).Exp(d.Params.g, r, d.Params.p)
	ciphertext[0] = c
	dd := new(big.Int).Exp(d.Params.h, r, d.Params.p)
	ciphertext[1] = dd

	for i := 0; i < len(x); i++ {
		// e_i = h_i^r * g^x_i
		// e_i = mpk[i]^r * g^x_i
		t1 := new(big.Int).Exp(masterPubKey[i], r, d.Params.p)
		t2 := internal.ModExp(d.Params.g, x[i], d.Params.p)
		ct := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.p)
		ciphertext[i+2] = ct
	}

	return data.NewVector(ciphertext), nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *Damgard) Decrypt(cipher data.Vector, key *DamgardDerivedKey, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.bound); err != nil {
		return nil, err
	}

	num := big.NewInt(1)
	for i, ct := range cipher[2:] {
		t1 := internal.ModExp(ct, y[i], d.Params.p)
		num = num.Mod(new(big.Int).Mul(num, t1), d.Params.p)
	}

	t1 := new(big.Int).Exp(cipher[0], key.key1, d.Params.p)
	t2 := new(big.Int).Exp(cipher[1], key.key2, d.Params.p)

	denom := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.p)
	denomInv := new(big.Int).ModInverse(denom, d.Params.p)
	r := new(big.Int).Mod(new(big.Int).Mul(num, denomInv), d.Params.p)

	order := new(big.Int).Sub(d.Params.p, big.NewInt(1))
	bSquared := new(big.Int).Exp(d.Params.bound, big.NewInt(2), big.NewInt(0))
	bound := new(big.Int).Mul(big.NewInt(int64(d.Params.l)), bSquared)

	calc, err := dlog.NewCalc().InZp(d.Params.p, order)
	if err != nil {
		return nil, err
	}
	calc = calc.WithNeg()

	res, err := calc.WithBound(bound).BabyStepGiantStep(r, d.Params.g)
	return res, err
}
