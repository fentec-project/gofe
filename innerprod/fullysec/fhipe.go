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
	"github.com/fentec-project/bn256"
	"crypto/rand"
	"github.com/fentec-project/gofe/sample"
)

// L (int): The length of vectors to be encrypted.
// Bound (int): The value by which coordinates of vectors x and y are bounded.
// G (int): Generator of a cyclic group Z_P: G**(Q) = 1 (mod P).
// H (int): Generator of a cyclic group Z_P: H**(Q) = 1 (mod P).
// P (int): Modulus - we are operating in a cyclic group Z_P.
// Q (int): Multiplicative order of G and H.
type FHIPEParams struct {
	L     int
	Bound *big.Int
}

// Damgard represents a scheme instantiated from the DDH assumption
// based on DDH variant of:
// Agrawal, Shweta, Libert, and Stehle:
// "Fully secure functional encryption for inner products,
// from standard assumptions".
type FHIPE struct {
	Params *FHIPEParams
}

// NewDamgard configures a new instance of the scheme.
// It accepts the length of input vectors l, the bit length of the
// modulus (we are operating in the Z_p group), and a bound by which
// coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition l * bound² is >= order of the cyclic
// group.
func NewFHIPE(l int, bound *big.Int) (*FHIPE, error) {
	bSquared := new(big.Int).Exp(bound, big.NewInt(2), nil)
	prod := new(big.Int).Mul(big.NewInt(int64(2*l)), bSquared)
	if prod.Cmp(bn256.Order) > 0 {
		return nil, fmt.Errorf("2 * l * bound^2 should be smaller than group order")
	}

	return &FHIPE{
		Params: &FHIPEParams{
			L:     l,
			Bound: bound}}, nil
}

// NewDamgardFromParams takes configuration parameters of an existing
// Damgard scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new Damgard instance.
func NewFHIPEFromParams(params *FHIPEParams) *FHIPE {
	return &FHIPE{
		Params: params,
	}
}

// DamgardSecKey is a secret key for Damgard scheme.
type FHIPESecKey struct {
	G1 *bn256.G1
	G2 *bn256.G2
	B data.Matrix
	BStar data.Matrix
}

// GenerateMasterKeys generates a master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *FHIPE) GenerateMasterKey() (*FHIPESecKey, error) {
	_, g1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, g2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, err
	}

	sampler := sample.NewUniform(bn256.Order)
	b, err := data.NewRandomMatrix(d.Params.L, d.Params.L, sampler)
	if err != nil {
		return nil, err
	}

	bStar, err := b.InverseMod(bn256.Order)
	if err != nil {
		return nil, err
	}
	bStar = bStar.Transpose()
	det, err := bStar.Determinant()
	if err != nil {
		return nil, err
	}
	bStar = bStar.MulScalar(det)
	bStar = bStar.Mod(bn256.Order)

	return &FHIPESecKey{G1: g1, G2: g2, B: b, BStar: bStar}, nil
}

// DamgardDerivedKey is a functional encryption key for Damgard scheme.
type FHIPEDerivedKey struct {
	K1 *bn256.G1
	K2 data.VectorG1
}

// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *FHIPE) DeriveKey(masterKey *FHIPESecKey, y data.Vector) (*FHIPEDerivedKey, error) {
	if err := y.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}
	if len(y) != d.Params.L {
		return nil, fmt.Errorf("vector dimension error")
	}

	sampler := sample.NewUniform(bn256.Order)
	alpha, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	det, err := masterKey.B.Determinant()
	if err != nil {
		return nil, err
	}
	k1 := new(bn256.G1).ScalarMult(masterKey.G1, det)
	k1.ScalarMult(k1, alpha)

	alphaBY, err := masterKey.B.MulVec(y)
	alphaBY = alphaBY.MulScalar(alpha)


	return &DamgardDerivedKey{Key1: k1, Key2: k2}, nil
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *Damgard) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	r, err := emmy.GetRandomIntFromRange(big.NewInt(2), d.Params.Q)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]*big.Int, len(x)+2)
	// c = g^r
	// dd = h^r
	c := new(big.Int).Exp(d.Params.G, r, d.Params.P)
	ciphertext[0] = c
	dd := new(big.Int).Exp(d.Params.H, r, d.Params.P)
	ciphertext[1] = dd

	for i := 0; i < len(x); i++ {
		// e_i = h_i^r * g^x_i
		// e_i = mpk[i]^r * g^x_i
		t1 := new(big.Int).Exp(masterPubKey[i], r, d.Params.P)
		t2 := internal.ModExp(d.Params.G, x[i], d.Params.P)
		ct := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.P)
		ciphertext[i+2] = ct
	}

	return data.NewVector(ciphertext), nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *Damgard) Decrypt(cipher data.Vector, key *DamgardDerivedKey, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	num := big.NewInt(1)
	for i, ct := range cipher[2:] {
		t1 := internal.ModExp(ct, y[i], d.Params.P)
		num = num.Mod(new(big.Int).Mul(num, t1), d.Params.P)
	}

	t1 := new(big.Int).Exp(cipher[0], key.Key1, d.Params.P)
	t2 := new(big.Int).Exp(cipher[1], key.Key2, d.Params.P)

	denom := new(big.Int).Mod(new(big.Int).Mul(t1, t2), d.Params.P)
	denomInv := new(big.Int).ModInverse(denom, d.Params.P)
	r := new(big.Int).Mod(new(big.Int).Mul(num, denomInv), d.Params.P)

	bSquared := new(big.Int).Exp(d.Params.Bound, big.NewInt(2), big.NewInt(0))
	bound := new(big.Int).Mul(big.NewInt(int64(d.Params.L)), bSquared)

	calc, err := dlog.NewCalc().InZp(d.Params.P, d.Params.Q)
	if err != nil {
		return nil, err
	}
	calc = calc.WithNeg()

	res, err := calc.WithBound(bound).BabyStepGiantStep(r, d.Params.G)
	return res, err
}
