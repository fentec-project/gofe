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

	"crypto/rand"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
)

// L (int): The length of vectors to be encrypted.
// BoundX (int): The value by which coordinates of encrypted vectors x are bounded.
// BoundY (int): The value by which coordinates of inner product vectors y are bounded.
type FHIPEParams struct {
	L      int
	BoundX *big.Int
	BoundY *big.Int
}

// FHIPE represents a Function Hiding Inner Product Encryption scheme
// based on the paper by Kim, Lewi, Mandal, Montgomery, Roy, Wu:
// "Function-Hiding Inner Product Encryption is Practical".
// It allows to encrypt a vector x and generate a secret key based
// in an inner product vector y so that a deryptor can decrypt the
// inner product <x,y> without revealing x or y.
// The struct contains the shared choice for parameters on which
// the functionality of the scheme depend.
type FHIPE struct {
	Params *FHIPEParams
}

// NewFHIPE configures a new instance of the scheme.
// It accepts the length of input vectors l, a bound by which
// the coordinates of encryption vectors are bounded, and similarly a
// bound by which the coordinates of inner product vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if the possible decryption value is to big.
func NewFHIPE(l int, boundX, boundY *big.Int) (*FHIPE, error) {
	boundXY := new(big.Int).Mul(boundX, boundY)
	prod := new(big.Int).Mul(big.NewInt(int64(2*l)), boundXY)
	if prod.Cmp(bn256.Order) > 0 {
		return nil, fmt.Errorf("2 * l * boundX * boundY should be smaller than group order")
	}

	return &FHIPE{
		Params: &FHIPEParams{
			L:      l,
			BoundX: boundX,
			BoundY: boundY}}, nil
}

// NewFHIPEFromParams takes configuration parameters of an existing
// FHIPE scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new FHIPE instance.
func NewFHIPEFromParams(params *FHIPEParams) *FHIPE {
	return &FHIPE{
		Params: params,
	}
}

// FHIPESecKey is a secret key for FHIPE scheme.
type FHIPESecKey struct {
	G1    *bn256.G1
	G2    *bn256.G2
	B     data.Matrix
	BStar data.Matrix
}

// GenerateMasterKey generates a master secret key for the scheme.
// It returns an error in case master key could not be generated.
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

	bStar, det, err := b.InverseModGauss(bn256.Order)
	if err != nil {
		return nil, err
	}
	bStar = bStar.Transpose()
	bStar = bStar.MulScalar(det)
	bStar = bStar.Mod(bn256.Order)

	return &FHIPESecKey{G1: g1, G2: g2, B: b, BStar: bStar}, nil
}

// FHIPEDerivedKey is a functional encryption key for FHIPE scheme.
type FHIPEDerivedKey struct {
	K1 *bn256.G1
	K2 data.VectorG1
}

// DeriveKey takes a master key and input vector y, and returns a
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *FHIPE) DeriveKey(y data.Vector, masterKey *FHIPESecKey) (*FHIPEDerivedKey, error) {
	if err := y.CheckBound(d.Params.BoundY); err != nil {
		return nil, err
	}
	if len(y) != d.Params.L {
		return nil, fmt.Errorf("vector dimension error")
	}
	if masterKey.B.Rows() != d.Params.L {
		return nil, fmt.Errorf("master key dimensions error")
	}

	sampler := sample.NewUniform(bn256.Order)
	alpha, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	det, err := masterKey.B.DeterminantGauss(bn256.Order)
	if err != nil {
		return nil, err
	}

	k1 := new(bn256.G1).ScalarMult(masterKey.G1, det)
	k1.ScalarMult(k1, alpha)

	alphaBY, err := masterKey.B.MulVec(y)
	if err != nil {
		return nil, err
	}
	alphaBY = alphaBY.MulScalar(alpha)
	alphaBY = alphaBY.Mod(bn256.Order)
	g1Vec := make(data.VectorG1, d.Params.L)
	for i := 0; i < d.Params.L; i++ {
		g1Vec[i] = new(bn256.G1).Set(masterKey.G1)
	}
	k2 := alphaBY.MulVecG1(g1Vec)

	return &FHIPEDerivedKey{K1: k1, K2: k2}, nil
}

// FHIPECipher is a functional encryption key for FHIPE scheme.
type FHIPECipher struct {
	C1 *bn256.G2
	C2 data.VectorG2
}

// Encrypt encrypts input vector x with the provided master key and returns a ciphertext.
// If encryption failed, error is returned.
func (d *FHIPE) Encrypt(x data.Vector, masterKey *FHIPESecKey) (*FHIPECipher, error) {
	if err := x.CheckBound(d.Params.BoundX); err != nil {
		return nil, err
	}
	if len(x) != d.Params.L {
		return nil, fmt.Errorf("vector dimension error")
	}
	if masterKey.B.Rows() != d.Params.L {
		return nil, fmt.Errorf("master key dimensions error")
	}

	sampler := sample.NewUniform(bn256.Order)
	beta, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	c1 := new(bn256.G2).ScalarMult(masterKey.G2, beta)

	betaBStarX, err := masterKey.BStar.MulVec(x)
	if err != nil {
		return nil, err
	}
	betaBStarX = betaBStarX.MulScalar(beta)
	betaBStarX = betaBStarX.Mod(bn256.Order)
	g2Vec := make(data.VectorG2, d.Params.L)
	for i := 0; i < d.Params.L; i++ {
		g2Vec[i] = new(bn256.G2).Set(masterKey.G2)
	}
	c2 := betaBStarX.MulVecG2(g2Vec)

	return &FHIPECipher{C1: c1, C2: c2}, nil
}

// Decrypt accepts the ciphertext and functional encryption key.
// It returns the inner product of x and y. If decryption failed,
// an error is returned.
func (d *FHIPE) Decrypt(cipher *FHIPECipher, key *FHIPEDerivedKey) (*big.Int, error) {
	if len(cipher.C2) != d.Params.L || len(key.K2) != d.Params.L {
		return nil, fmt.Errorf("key or cipher length error")
	}

	d1 := bn256.Pair(key.K1, cipher.C1)

	d2 := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < d.Params.L; i++ {
		pairedI := bn256.Pair(key.K2[i], cipher.C2[i])
		d2 = new(bn256.GT).Add(pairedI, d2)

	}

	// calculate the upper bound of the result needed for the
	// discrete logarithm computation
	boundXY := new(big.Int).Mul(d.Params.BoundX, d.Params.BoundY)
	bound := new(big.Int).Mul(big.NewInt(int64(d.Params.L)), boundXY)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(d2, d1)
	return dec, err
}
