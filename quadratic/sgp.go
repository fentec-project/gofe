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

package quadratic

import (
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
)

// SGP implements efficient FE scheme for quadratic multi-variate polynomials
// based on  Sans, Gay and Pointcheval:
// "Reading in the Dark: Classifying Encrypted Digits with
// Functional Encryption".
// See paper: https://eprint.iacr.org/2018/206.pdf which is based on bilinear pairings.
// It offers adaptive security under chosen-plaintext attacks (IND-CPA security).
// This is a secret key scheme, meaning that we need a master secret key to
// encrypt the messages.
// Assuming input vectors x and y, the SGP scheme allows the decryptor to
// calculate x^T * F * y, where F is matrix that represents the function,
// and vectors x, y are only known to the encryptor, but not to decryptor.
type SGP struct {
	// length of vectors x and y (matrix F is N x N)
	N int
	// Modulus for ciphertext and keys
	mod *big.Int

	// TODO: If needed, bound can be changed to have different bounds for x, y, F.
	// The value by which elements of vectors x, y, and the
	// matrix F are bounded.
	Bound *big.Int

	gCalc    *dlog.CalcBN256
	gInvCalc *dlog.CalcBN256
}

// NewSGP configures a new instance of the SGP scheme.
// It accepts the length of input vectors n and the upper bound b
// for coordinates of input vectors x, y, and the function
// matrix F.
func NewSGP(n int, b *big.Int) *SGP {
	return &SGP{
		N:        n,
		mod:      bn256.Order,
		Bound:    b,
		gCalc:    dlog.NewCalc().InBN256(), //.WithBound(b),
		gInvCalc: dlog.NewCalc().InBN256(), //.WithBound(b),
	}
}

// SGPSecKey represents a master secret key for the SGP scheme.
// An instance of this type is returned by the
// GenerateMasterKey method.
type SGPSecKey struct {
	S data.Vector
	T data.Vector
}

// NewSGPSecKey constructs an instance of SGPSecKey.
func NewSGPSecKey(s, t data.Vector) *SGPSecKey {
	return &SGPSecKey{
		S: s,
		T: t,
	}
}

// GenerateMasterKey generates a master secret key for the
// SGP scheme. It returns an error if the secret key could
// not be generated.
func (q *SGP) GenerateMasterKey() (*SGPSecKey, error) {
	// msk is random s, t from Z_p^n
	sampler := sample.NewUniform(q.mod)
	s, err := data.NewRandomVector(q.N, sampler)
	if err != nil {
		return nil, err
	}
	t, err := data.NewRandomVector(q.N, sampler)
	if err != nil {
		return nil, err
	}

	return NewSGPSecKey(s, t), nil
}

// SGPCipher represents a ciphertext. An instance of this type
// is returned as a result of the Encrypt method.
type SGPCipher struct {
	G1MulGamma *bn256.G1
	AMulG1     []data.VectorG1
	BMulG2     []data.VectorG2
}

// NewSGPCipher constructs an instance of SGPCipher.
func NewSGPCipher(g1MulGamma *bn256.G1, aMulG1 []data.VectorG1,
	bMulG2 []data.VectorG2) *SGPCipher {
	return &SGPCipher{
		G1MulGamma: g1MulGamma,
		AMulG1:     aMulG1,
		BMulG2:     bMulG2,
	}
}

// Encrypt encrypts input vectors x and y with the
// master secret key msk. It returns the appropriate ciphertext.
// If ciphertext could not be generated, it returns an error.
func (q *SGP) Encrypt(x, y data.Vector, msk *SGPSecKey) (*SGPCipher, error) {
	sampler := sample.NewUniform(q.mod)
	gamma, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	W, err := data.NewRandomMatrix(2, 2, sampler)
	if err != nil {
		return nil, err
	}

	WInv, err := W.InverseMod(q.mod)
	if err != nil {
		return nil, err
	}

	WInvT := WInv.Transpose()

	a := make([]data.Vector, q.N)
	b := make([]data.Vector, q.N)
	for i := 0; i < q.N; i++ {
		// v = (x_i, gamma * s_i)
		tmp := new(big.Int).Mul(gamma, msk.S[i])
		tmp.Mod(tmp, q.mod)
		v := data.NewVector([]*big.Int{x[i], tmp})
		ai, err := WInvT.MulVec(v)
		if err != nil {
			return nil, err
		}
		a[i] = ai

		// v = (y_i, -t_i)
		tiNeg := new(big.Int).Sub(q.mod, msk.T[i])
		bi, err := W.MulVec(data.NewVector([]*big.Int{y[i], tiNeg}))
		if err != nil {
			return nil, err
		}
		b[i] = bi
	}
	aMulG1 := make([]data.VectorG1, q.N)
	bMulG2 := make([]data.VectorG2, q.N)
	for i := range a {
		aMulG1[i] = a[i].MulG1()
		bMulG2[i] = b[i].MulG2()
	}

	c := NewSGPCipher(new(bn256.G1).ScalarBaseMult(gamma), aMulG1, bMulG2)

	return c, nil
}

// DeriveKey derives the functional encryption key for the scheme.
// It returns an error if the key could not be derived.
func (q *SGP) DeriveKey(msk *SGPSecKey, F data.Matrix) (*bn256.G2, error) {
	// F is matrix and represents function (x, y) -> Σ f_i,j * x_i * y_i.
	// Functional encryption key is g2 * f(s, t).
	v, err := F.MulXMatY(msk.S, msk.T)
	if err != nil {
		return nil, err
	}

	tmp := new(big.Int).Set(v)
	e := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	if tmp.Cmp(big.NewInt(0)) < 0 {
		tmp.Neg(tmp)
		e.Neg(e)
	}

	return new(bn256.G2).ScalarMult(e, tmp), nil
}

// Decrypt decrypts the ciphertext c with the derived functional
// encryption key key in order to obtain function x^T * F * y.
func (q *SGP) Decrypt(c *SGPCipher, key *bn256.G2, F data.Matrix) (*big.Int, error) {
	prod := bn256.Pair(c.G1MulGamma, key)
	zero := big.NewInt(0)

	for i, row := range F {
		for j, rowEl := range row {
			if rowEl.Cmp(zero) != 0 {
				e1 := bn256.Pair(c.AMulG1[i][0], c.BMulG2[j][0])
				e2 := bn256.Pair(c.AMulG1[i][1], c.BMulG2[j][1])
				e := new(bn256.GT).Add(e1, e2)

				tmp := new(big.Int).Set(rowEl)
				if tmp.Cmp(zero) == -1 {
					tmp.Neg(tmp)
					e.Neg(e)
				}

				t := new(bn256.GT).ScalarMult(e, tmp)
				prod.Add(prod, t)
			}
		}
	}

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)

	// b: b = n^2 * b^3
	b3 := new(big.Int).Exp(q.Bound, big.NewInt(3), nil)
	n2 := new(big.Int).Exp(big.NewInt(int64(q.N)), big.NewInt(2), nil)
	b := new(big.Int).Mul(n2, b3)

	return q.gCalc.WithBound(b).WithNeg().BabyStepGiantStep(prod, g)
}
