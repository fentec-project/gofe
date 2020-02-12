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
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/internal/dlog"
)

// DamgardParams includes public parameters for the Damgard inner
// product scheme.
// L (int): The length of vectors to be encrypted.
// Bound (int): The value by which coordinates of vectors x and y are bounded.
// G (int): Generator of a cyclic group Z_P: G**(Q) = 1 (mod P).
// H (int): Generator of a cyclic group Z_P: H**(Q) = 1 (mod P).
// P (int): Modulus - we are operating in a cyclic group Z_P.
// Q (int): Multiplicative order of G and H.
type PartFHIPEParams struct {
	L int
	K int
	Bound      *big.Int
	p big.Int
}

// Damgard represents a scheme instantiated from the DDH assumption
// based on DDH variant of:
// Agrawal, Shweta, Libert, and Stehle:
// "Fully secure functional encryption for inner products,
// from standard assumptions".
type PartFHIPE struct {
	Params *PartFHIPEParams
}

// NewDamgard configures a new instance of the scheme.
// It accepts the length of input vectors l, the bit length of the
// modulus (we are operating in the Z_p group), and a bound by which
// coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition l * bound² is >= order of the cyclic
// group.
func NewPartFHIPE(l, k int, bound *big.Int) *PartFHIPE {
	return &PartFHIPE{
		Params: &PartFHIPEParams{
			L:     l,
			K: k,
			Bound: bound,
		},
	}
}


// NewDamgardFromParams takes configuration parameters of an existing
// Damgard scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new Damgard instance.
func NewPartFHIPEFromParams(params *PartFHIPEParams) *PartFHIPE {
	return &PartFHIPE{
		Params: params,
	}
}

// DamgardSecKey is a secret key for Damgard scheme.
type PartFHIPESecKey struct {
	B data.VectorG2
	V data.Matrix
	U data.Matrix
}

// DamgardSecKey is a secret key for Damgard scheme.
type PartFHIPEPubKey struct {
	A data.VectorG1
	Ua data.VectorG1
	VtM data.MatrixG1
	MG1 data.MatrixG1
}

// GenerateMasterKeys generates a master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *PartFHIPE) GenerateKeys(M data.Matrix) (*PartFHIPEPubKey, *PartFHIPESecKey, error) {
	if d.Params.L != M.Rows() || d.Params.K != M.Cols() {
		return nil, nil, fmt.Errorf("dimensions of the given matrix do not match dimensions of the scheme")
	}
	sampler := sample.NewUniform(bn256.Order)
	//sampler = sample.NewUniformRange(big.NewInt(0), big.NewInt(1))
	//sampler2 := sample.NewUniformRange(big.NewInt(0), big.NewInt(1))


	aVec := make(data.Vector, 2)
	bVec := make(data.Vector, 2)

	aVec[0] = big.NewInt(1)
	bVec[0] = big.NewInt(1)

	x, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	aVec[1] = x

	x, err = sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	bVec[1] = x

	a := aVec.MulG1()
	b := bVec.MulG2()

	U, err := data.NewRandomMatrix(d.Params.L + 2, 2, sampler)
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
	Ua := UaVec.MulG1()

	VtMMat, err := V.Transpose().Mul(M)
	if err != nil {
		return nil, nil, err
	}
	VtM := VtMMat.MulG1()

	MG1 := M.MulG1()

	return &PartFHIPEPubKey{A: a, Ua: Ua, VtM: VtM, MG1: MG1},
		   &PartFHIPESecKey{B: b, V: V, U: U},
		   nil
}

// TODO: maybe optimize to b being vector
// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (d *PartFHIPE) DeriveKey(y data.Vector, secKey *PartFHIPESecKey) (data.VectorG2, error) {
	if err := y.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	sampler := sample.NewUniform(bn256.Order)
	//sampler = sample.NewUniformRange(big.NewInt(0), big.NewInt(1))

	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	//key2 := make(data.VectorG2, d.Params.L + 2)
	bs := secKey.B.MulScalar(s)

	Vbs, err := secKey.V.MatMulVecG2(bs)
	if err != nil {
		return nil, err
	}
	yG2 := y.MulG2()
	YVbs := Vbs.Add(yG2)
	key2 := append(bs, YVbs...)
	//key2[:2] = bs
	//key2[2:] = YVbs

	key1, err := secKey.U.Transpose().MatMulVecG2(key2)
	if err != nil {
		return nil, err
	}
	key1 = key1.Neg()

	//key := make(data.VectorG2, d.Params.L + 4)
	//key[:2] = key1
	//key[2:] = key2
	key := append(key1, key2...)

	return key, nil
}




// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *PartFHIPE) Encrypt(x data.Vector, pubKey *PartFHIPEPubKey) (data.VectorG1, error) {
	// todo: different check
	if err := x.CheckBound(d.Params.Bound); err != nil {
		return nil, err
	}

	sampler := sample.NewUniform(bn256.Order)
	//sampler = sample.NewUniformRange(big.NewInt(0), big.NewInt(1))

	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	c := pubKey.A.MulScalar(r)
	Uc := pubKey.Ua.MulScalar(r)

	Mx := pubKey.MG1.MulVector(x)
	VtMx := pubKey.VtM.MulVector(x)
	VtMxNeg := VtMx.Neg()
	cipher2 := append(VtMxNeg, Mx...)
	cipher2add := cipher2.Add(Uc)

	cipher := append(c, cipher2add...)

	//fmt.Println(c, cipher2, cipher)

	return cipher, nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *PartFHIPE) PartDecrypt(cipher data.VectorG1, feKey data.VectorG2) *bn256.GT {
	dec := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < d.Params.L + 4; i++ {
		pairedI := bn256.Pair(cipher[i], feKey[i])
		dec = new(bn256.GT).Add(pairedI, dec)
	}

	return dec
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, error is returned.
func (d *PartFHIPE) Decrypt(cipher data.VectorG1, feKey data.VectorG2) (*big.Int, error) {
	dec := d.PartDecrypt(cipher, feKey)

	//bSquared := new(big.Int).Mul(d.Params.Bound, d.Params.Bound)
	//bound := new(big.Int).Mul(big.NewInt(int64(d.Params.L)), bSquared)
	calc := dlog.NewCalc().InBN256().WithNeg()

	//fmt.Println("dec", dec, new(bn256.GT).ScalarBaseMult(big.NewInt(0)))
	res, err := calc.BabyStepGiantStep(dec, new(bn256.GT).ScalarBaseMult(big.NewInt(1)))

	return res, err
}
