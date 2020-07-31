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
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
)

// QuadParams includes public parameters for the partially
// function hiding inner product scheme.
// PartFHIPE: underlying partially function hiding scheme.
// N (int): The length of x vectors to be encrypted.
// M (int): The length of y vectors to be encrypted.
// Bound (*big.Int): The value by which coordinates of vectors x, y and F are bounded.
type QuadParams struct {
	PartFHIPE *fullysec.PartFHIPE
	// N should be greater or equal to M
	N int // length of vectors x
	M int // length of vectors y
	// The value by which elements of vectors x, y, and the
	// matrix F are bounded.
	Bound *big.Int
}

// Quad represents a public key FE scheme for quadratic multi-variate polynomials.
// More precisely, it allows to encrypt vectors x and y using public key,
// derive a functional encryption key corresponding to a matrix F, and
// decrypt value x^T * F * y from encryption of x, y and functional key, without
// reveling any other information about x or y. The scheme is based on
// a paper by Romain Gay: "A New Paradigm for Public-Key Functional
// Encryption for Degree-2 Polynomials".
// The scheme uses an underling partially function hiding inner product
// FE scheme.
type Quad struct {
	Params *QuadParams
}

// NewQuad configures a new instance of the quadratic public key scheme.
// It accepts the length of input vectors n and m and the upper bound b
// for coordinates of input vectors x, y, and the function
// matrix F. Parameter n should be greater or equal to m.
func NewQuad(n, m int, b *big.Int) (*Quad, error) {
	if n < m {
		return nil, fmt.Errorf("n should be greater or equal to m")
	}
	bound := new(big.Int).Set(b)
	bound.Exp(bound, big.NewInt(3), nil)
	bound.Mul(big.NewInt(int64(2*n*m)), bound)
	if bound.Cmp(bn256.Order) > 0 {
		return nil, fmt.Errorf("bound and n, m too big for the group")
	}

	partFHIPE, err := fullysec.NewPartFHIPE(2*m+n*3, nil)
	if err != nil {
		return nil, err
	}

	return &Quad{
		Params: &QuadParams{
			PartFHIPE: partFHIPE,
			N:         n,
			M:         m,
			Bound:     new(big.Int).Set(b),
		},
	}, nil
}

// NewQuadFromParams takes configuration parameters of an existing
// Quad instance, and reconstructs the scheme with the same configuration
// parameters. It returns a new Quad instance.
func NewQuadFromParams(params *QuadParams) *Quad {
	return &Quad{
		Params: params,
	}
}

// QuadPubKey represents a public key for the scheme.
// An instance of this type is returned by the
// GenerateKeys method.
type QuadPubKey struct {
	Ua     data.VectorG1
	VB     data.MatrixG2
	PubIPE *fullysec.PartFHIPEPubKey
}

// QuadSecKey represents a master secret key for the scheme.
// An instance of this type is returned by the
// GenerateKeys method.
type QuadSecKey struct {
	U      data.Matrix
	V      data.Matrix
	SecIPE *fullysec.PartFHIPESecKey
}

// GenerateKeys generates a public key and master secret
// key for the scheme. It returns an error if the keys could
// not be generated.
func (q *Quad) GenerateKeys() (*QuadPubKey, *QuadSecKey, error) {
	sampler := sample.NewUniform(bn256.Order)
	var err error

	// create a vector a over DDH distribution
	a := make(data.Vector, 2)
	a[0] = big.NewInt(1)
	a[1], err = sampler.Sample()
	if err != nil {
		return nil, nil, err
	}

	// create a vector a over DLIN distribution
	B := make(data.Matrix, 3)
	B[0] = make(data.Vector, 2)
	B[0][1] = big.NewInt(0)
	B[0][0], err = sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	B[1] = make(data.Vector, 2)
	B[1][0] = big.NewInt(0)
	B[1][1], err = sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	B[2] = data.NewConstantVector(2, big.NewInt(1))

	// sample matrices U, V and calculate Ua, VB
	U, err := data.NewRandomMatrix(q.Params.N, 2, sampler)
	if err != nil {
		return nil, nil, err
	}
	V, err := data.NewRandomMatrix(q.Params.M, 3, sampler)
	if err != nil {
		return nil, nil, err
	}

	UaVec, err := U.MulVec(a)
	if err != nil {
		return nil, nil, err
	}
	UaVec = UaVec.Mod(bn256.Order)
	Ua := UaVec.MulG1()

	VBMat, err := V.Mul(B)
	if err != nil {
		return nil, nil, err
	}
	VBMat = VBMat.Mod(bn256.Order)
	VB := VBMat.MulG2()

	// assemble matrix M
	// upper part
	IdnVB, err := data.Identity(q.Params.M, q.Params.M).JoinCols(VBMat)
	if err != nil {
		return nil, nil, err
	}
	aMat := data.Matrix{a}.Transpose()
	aTensorIdnVB := aMat.Tensor(IdnVB)
	aTensorIdnVB = aTensorIdnVB.Mod(bn256.Order)
	M0, err := aTensorIdnVB.JoinCols(data.NewConstantMatrix(2*q.Params.M, q.Params.N*2, big.NewInt(0)))
	if err != nil {
		return nil, nil, err
	}
	// lower part
	IdnB := data.Identity(q.Params.N, q.Params.N).Tensor(B)
	M1, err := data.NewConstantMatrix(q.Params.N*3, IdnVB.Cols(), big.NewInt(0)).JoinCols(IdnB)
	if err != nil {
		return nil, nil, err
	}
	// together
	M, err := M0.JoinRows(M1)
	if err != nil {
		return nil, nil, err
	}

	pkIPE, skIPE, err := q.Params.PartFHIPE.GenerateKeys(M)
	if err != nil {
		return nil, nil, err
	}

	pk := &QuadPubKey{Ua: Ua, VB: VB, PubIPE: pkIPE}
	sk := &QuadSecKey{U: U, V: V, SecIPE: skIPE}

	return pk, sk, nil
}

// QuadCipher represents ciphertext in the scheme.
type QuadCipher struct {
	Cx   data.VectorG1
	Cy   data.VectorG2
	CIPE data.VectorG1
}

// Encrypt encrypts input vectors x and y with the given
// public key. It returns the appropriate ciphertext.
// If the ciphertext could not be generated, it returns an error.
func (q *Quad) Encrypt(x, y data.Vector, pubKey *QuadPubKey) (*QuadCipher, error) {
	if len(x) != q.Params.N || len(y) != q.Params.M {
		return nil, fmt.Errorf("dimensions of vectors are incorrect")
	}
	if err := x.CheckBound(q.Params.Bound); err != nil {
		return nil, err
	}
	if err := y.CheckBound(q.Params.Bound); err != nil {
		return nil, err
	}

	sampler := sample.NewUniform(bn256.Order)
	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, err
	}

	Uar := pubKey.Ua.MulScalar(r)
	xG1 := x.MulG1()
	Cx := xG1.Add(Uar)

	VBs := pubKey.VB.MulVector(s)
	yG2 := y.MulG2()
	Cy := yG2.Add(VBs)

	ys := append(y, s...)
	rys := ys.MulScalar(r)
	xs := x.Tensor(s)
	xIPE := append(rys, xs...)
	xIPE = xIPE.Mod(bn256.Order)
	cIPE, err := q.Params.PartFHIPE.Encrypt(xIPE, pubKey.PubIPE)
	if err != nil {
		return nil, err
	}

	return &QuadCipher{Cx: Cx, Cy: Cy, CIPE: cIPE}, nil
}

// DeriveKey derives the functional encryption key for the scheme.
// It returns an error if the key could not be derived.
func (q *Quad) DeriveKey(secKey *QuadSecKey, F data.Matrix) (data.VectorG2, error) {
	if F.Rows() != q.Params.N || F.Cols() != q.Params.M {
		return nil, fmt.Errorf("dimensions of the given matrix are incorrect")
	}

	UtF, err := secKey.U.Transpose().Mul(F)
	if err != nil {
		return nil, err
	}
	UtF = UtF.Mod(bn256.Order)
	UTFvec := UtF.ToVec()

	FV, err := F.Mul(secKey.V)
	if err != nil {
		return nil, err
	}
	FV = FV.Mod(bn256.Order)
	FVvec := FV.ToVec()

	yIPE := append(UTFvec, FVvec...)
	feKey, err := q.Params.PartFHIPE.DeriveKey(yIPE, secKey.SecIPE)

	return feKey, err
}

// Decrypt decrypts the ciphertext c with the derived functional
// encryption key key in order to obtain function x^T * F * y.
func (q *Quad) Decrypt(c *QuadCipher, feKey data.VectorG2, F data.Matrix) (*big.Int, error) {
	if len(feKey) != q.Params.PartFHIPE.Params.L+4 {
		return nil, fmt.Errorf("dimensions of the given FE key are incorrect")
	}
	if F.Rows() != q.Params.N || F.Cols() != q.Params.M {
		return nil, fmt.Errorf("dimensions of the given matrix are incorrect")
	}

	d, err := q.Params.PartFHIPE.PartDecrypt(c.CIPE, feKey)
	if err != nil {
		return nil, err
	}

	FCy, err := F.MatMulVecG2(c.Cy)
	if err != nil {
		return nil, err
	}

	dec := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < q.Params.N; i++ {
		pairedI := bn256.Pair(c.Cx[i], FCy[i])
		dec = new(bn256.GT).Add(pairedI, dec)
	}
	d = new(bn256.GT).Neg(d)
	dec = new(bn256.GT).Add(dec, d)

	// get upper bounds
	b3 := new(big.Int).Exp(q.Params.Bound, big.NewInt(3), nil)
	b := new(big.Int).Mul(b3, big.NewInt(int64(q.Params.N*q.Params.M)))
	calc := dlog.NewCalc().InBN256().WithBound(b).WithNeg()

	res, err := calc.BabyStepGiantStep(dec, new(bn256.GT).ScalarBaseMult(big.NewInt(1)))

	return res, err
}
