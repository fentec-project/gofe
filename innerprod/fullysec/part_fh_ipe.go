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
)

// PartFHIPEParams includes public parameters for the partially
// function hiding inner product scheme.
// L (int): The length of vectors to be encrypted.
// Bound (*big.Int): The value by which coordinates of vectors x and y are bounded.
type PartFHIPEParams struct {
	L     int
	Bound *big.Int
}

// PartFHIPE represents a partially function hiding inner product
// FE scheme. A partially function hiding scheme is a public
// key FE scheme that allows to encrypt vectors and produce FE
// keys to be able to decrypt only the inner product of the encryption
// and chosen vector without revealing the encrypted or FE key vector.
// Public key encryption allows to encrypt only vectors from a chosen
// subspace. This way a functional encryption key does not reveal
// its corresponding inner product vector. Decryption of a
// ciphertext using FE key can be done without knowing the function.
// Additionally, owner of the secret key can encrypt any vector.
//
// The scheme is based on the paper by Romain Gay:
// "A New Paradigm for Public-Key Functional Encryption for
// Degree-2 Polynomials".
type PartFHIPE struct {
	Params *PartFHIPEParams
}

// NewPartFHIPE configures a new instance of the scheme.
// It accepts the length of input vectors l, and a bound by which
// the absolute values of the coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition 2* l * bound² is >= order of the cyclic
// group.
func NewPartFHIPE(l int, bound *big.Int) (*PartFHIPE, error) {
	var b *big.Int
	if bound != nil {
		b = new(big.Int).Set(bound)
		bSquared := new(big.Int).Mul(bound, bound)
		upper := new(big.Int).Mul(big.NewInt(int64(2*l)), bSquared)
		if upper.Cmp(bn256.Order) > 0 {
			return nil, fmt.Errorf("bound and l too big for the group")
		}
	}

	return &PartFHIPE{
		Params: &PartFHIPEParams{
			L:     l,
			Bound: b,
		},
	}, nil
}

// NewPartFHIPEFromParams takes configuration parameters of an existing
// PartFHIPE instance, and reconstructs the scheme with the same configuration
// parameters. It returns a new PartFHIPE instance.
func NewPartFHIPEFromParams(params *PartFHIPEParams) *PartFHIPE {
	return &PartFHIPE{
		Params: params,
	}
}

// PartFHIPESecKey is a secret key for the partially function hiding
// inner product scheme.
type PartFHIPESecKey struct {
	B data.Vector
	V data.Matrix
	U data.Matrix
}

// PartFHIPEPubKey is a public key for the partially function hiding
// inner product scheme.
type PartFHIPEPubKey struct {
	A   data.VectorG1
	Ua  data.VectorG1
	VtM data.MatrixG1
	M   data.Matrix
	MG1 data.MatrixG1
}

// GenerateKeys generates a master secret key and public key for the scheme.
// A matrix M needs to be specified so that the generated public key will
// allow to encrypt arbitrary vector in the span on the columns of M.
// It returns an error in case the keys could not be generated.
func (d *PartFHIPE) GenerateKeys(M data.Matrix) (*PartFHIPEPubKey, *PartFHIPESecKey, error) {
	if d.Params.L != M.Rows() {
		return nil, nil, fmt.Errorf("dimensions of the given matrix do not match dimensions of the scheme")
	}
	sampler := sample.NewUniform(bn256.Order)

	aVec := make(data.Vector, 2)
	aVec[0] = big.NewInt(1)
	x, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	aVec[1] = x

	b := make(data.Vector, 2)
	b[0] = big.NewInt(1)
	x, err = sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	b[1] = x

	a := aVec.MulG1()

	U, err := data.NewRandomMatrix(d.Params.L+2, 2, sampler)
	if err != nil {
		return nil, nil, err
	}

	V, err := data.NewRandomMatrix(d.Params.L, 2, sampler)
	if err != nil {
		return nil, nil, err
	}

	UaVec, err := U.MulVec(aVec)
	if err != nil {
		return nil, nil, err
	}
	UaVec = UaVec.Mod(bn256.Order)

	Ua := UaVec.MulG1()

	VtMMat, err := V.Transpose().Mul(M)
	if err != nil {
		return nil, nil, err
	}
	VtMMat = VtMMat.Mod(bn256.Order)
	VtM := VtMMat.MulG1()

	MG1 := M.MulG1()

	return &PartFHIPEPubKey{A: a, Ua: Ua, VtM: VtM, M: M.Copy(), MG1: MG1},
		&PartFHIPESecKey{B: b, V: V, U: U},
		nil
}

// DeriveKey takes input vector y and master secret key, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *PartFHIPE) DeriveKey(y data.Vector, secKey *PartFHIPESecKey) (data.VectorG2, error) {
	if len(y) != d.Params.L {
		return nil, fmt.Errorf("the dimension of the given vector does not match the dimension of the scheme")
	}
	if d.Params.Bound != nil {
		if err := y.CheckBound(d.Params.Bound); err != nil {
			return nil, err
		}
	}

	sampler := sample.NewUniform(bn256.Order)

	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	bs := secKey.B.MulScalar(s)
	bs = bs.Mod(bn256.Order)

	Vbs, err := secKey.V.MulVec(bs)
	if err != nil {
		return nil, err
	}
	YVbs := y.Add(Vbs)
	YVbs = YVbs.Mod(bn256.Order)
	key2 := append(bs, YVbs...)

	key1, err := secKey.U.Transpose().MulVec(key2)
	if err != nil {
		return nil, err
	}
	key1 = key1.Neg()
	key1 = key1.Mod(bn256.Order)

	key := append(key1, key2...)

	return key.MulG2(), nil
}

// Encrypt on input vector t encrypts vector x = Mt with the provided public key
// (matrix M is specified in the public key). It returns a ciphertext vector.
// Entries of Mt should not be greater then bound.
// If encryption fails, an error is returned.
func (d *PartFHIPE) Encrypt(t data.Vector, pubKey *PartFHIPEPubKey) (data.VectorG1, error) {
	x, err := pubKey.M.MulVec(t)
	if err != nil {
		return nil, err
	}
	if d.Params.Bound != nil {
		if err := x.CheckBound(d.Params.Bound); err != nil {
			return nil, err
		}
	}

	sampler := sample.NewUniform(bn256.Order)

	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	c := pubKey.A.MulScalar(r)
	Uc := pubKey.Ua.MulScalar(r)

	Mt := pubKey.MG1.MulVector(t)
	VtMt := pubKey.VtM.MulVector(t)
	VtMxNeg := VtMt.Neg()
	cipher2 := append(VtMxNeg, Mt...)
	cipher2add := cipher2.Add(Uc)

	cipher := append(c, cipher2add...)

	return cipher, nil
}

// SecEncrypt encrypts an arbitrary vector x using master secret key and
// public key. It returns a ciphertext vector. If encryption failed,
// an error is returned.
func (d *PartFHIPE) SecEncrypt(x data.Vector, pubKey *PartFHIPEPubKey, secKey *PartFHIPESecKey) (data.VectorG1, error) {
	if len(x) != d.Params.L {
		return nil, fmt.Errorf("the dimension of the given vector does not match the dimension of the scheme")
	}
	if d.Params.Bound != nil {
		if err := x.CheckBound(d.Params.Bound); err != nil {
			return nil, err
		}
	}

	sampler := sample.NewUniform(bn256.Order)

	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	c := pubKey.A.MulScalar(r)
	Uc := pubKey.Ua.MulScalar(r)

	Vtx, err := secKey.V.Transpose().MulVec(x)
	if err != nil {
		return nil, err
	}
	Vtx = Vtx.Neg().Mod(bn256.Order)

	VtxG1 := Vtx.MulG1()
	xG1 := x.MulG1()
	cipher2 := append(VtxG1, xG1...)
	cipher2add := cipher2.Add(Uc)

	cipher := append(c, cipher2add...)

	return cipher, nil
}

// PartDecrypt accepts the encrypted vector and functional encryption key. It
// returns the value d*[bn256.GT] where d is the inner product of x and y.
// To obtain a final result, calculating the discrete logarithm is needed.
func (d *PartFHIPE) PartDecrypt(cipher data.VectorG1, feKey data.VectorG2) (*bn256.GT, error) {
	if len(cipher) != d.Params.L+4 || len(feKey) != d.Params.L+4 {
		return nil, fmt.Errorf("the length of FE key or ciphertext does not match the dimension of the scheme")
	}
	dec := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < d.Params.L+4; i++ {
		pairedI := bn256.Pair(cipher[i], feKey[i])
		dec = new(bn256.GT).Add(pairedI, dec)
	}

	return dec, nil
}

// Decrypt accepts the encrypted vector and functional encryption key.
// It returns the inner product of x and y. If decryption failed, error is returned.
func (d *PartFHIPE) Decrypt(cipher data.VectorG1, feKey data.VectorG2) (*big.Int, error) {
	dec, err := d.PartDecrypt(cipher, feKey)
	if err != nil {
		return nil, err
	}
	calc := dlog.NewCalc().InBN256().WithNeg()

	if d.Params.Bound != nil {
		bSquared := new(big.Int).Mul(d.Params.Bound, d.Params.Bound)
		bound := new(big.Int).Mul(big.NewInt(int64(d.Params.L)), bSquared)
		calc = calc.WithBound(bound)
	}

	res, err := calc.BabyStepGiantStep(dec, new(bn256.GT).ScalarBaseMult(big.NewInt(1)))

	return res, err
}
