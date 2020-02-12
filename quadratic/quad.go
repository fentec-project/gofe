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
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"fmt"
)

// SGP implements efficient FE scheme for quadratic multi-variate polynomials
// based on Dufour Sans, Gay and Pointcheval:
// "Reading in the Dark: Classifying Encrypted Digits with
// Functional Encryption".
// See paper: https://eprint.iacr.org/2018/206.pdf which is based on bilinear pairings.
// It offers adaptive security under chosen-plaintext attacks (IND-CPA security).
// This is a secret key scheme, meaning that we need a master secret key to
// encrypt the messages.
// Assuming input vectors x and y, the SGP scheme allows the decryptor to
// calculate x^T * F * y, where F is matrix that represents the function,
// and vectors x, y are only known to the encryptor, but not to decryptor.
type Quad struct {
	PartFHIPE *fullysec.PartFHIPE
	// length of vectors x and y (matrix F is N x N)
	N int
	// Modulus for ciphertext and keys
	M int

	// The value by which elements of vectors x, y, and the
	// matrix F are bounded.
	Bound *big.Int

	GCalc    *dlog.CalcBN256
	GInvCalc *dlog.CalcBN256
}

// NewSGP configures a new instance of the SGP scheme.
// It accepts the length of input vectors n and the upper bound b
// for coordinates of input vectors x, y, and the function
// matrix F.
func NewQuad(n, m int, b *big.Int) *Quad {
	partFHIPE := fullysec.NewPartFHIPE(2*m + n*3, (m + 2) + n*2, bn256.Order)

	return &Quad{
		PartFHIPE: partFHIPE,
		N:        n,
		M:        m,
		Bound:    b,
		GCalc:    dlog.NewCalc().InBN256(), //.WithBound(b),
		GInvCalc: dlog.NewCalc().InBN256(), //.WithBound(b),
	}
}

// SGPSecKey represents a master secret key for the SGP scheme.
// An instance of this type is returned by the
// GenerateMasterKey method.
type QuadPubKey struct {
	Ua data.VectorG1
	VB data.MatrixG2
	PubIPE *fullysec.PartFHIPEPubKey
}

type QuadSecKey struct {
	U data.Matrix
	V data.Matrix
	SecIPE *fullysec.PartFHIPESecKey
}

// GenerateMasterKey generates a master secret key for the
// SGP scheme. It returns an error if the secret key could
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
	U, err := data.NewRandomMatrix(q.N, 2, sampler)
	if err != nil {
		return nil, nil, err
	}
	V, err := data.NewRandomMatrix(q.M, 3, sampler)
	if err != nil {
		return nil, nil, err
	}

	UaVec, err := U.MulVec(a)
	if err != nil {
		return nil, nil, err
	}
	Ua := UaVec.MulG1()

	VBMat, err := V.Mul(B)
	if err != nil {
		return nil, nil, err
	}
	VB := VBMat.MulG2()

	// assemble matrix M
	// upper part
	IdVB, err := data.Id(q.M, q.M).JoinCols(VBMat)
	if err != nil {
		return nil, nil, err
	}
	aMat := data.Matrix{a}.Transpose()
	//fmt.Println(aMat, IdVB)
	//fmt.Println(aMat.Rows(), IdVB.Rows())
	//fmt.Println(aMat.Cols(), IdVB.Cols())
	aTensorIdVB := aMat.Tensor(IdVB)
	//fmt.Println(aTensorIdVB)
	M0, err := aTensorIdVB.JoinCols(data.NewConstantMatrix(2 * q.M, q.N * 2, big.NewInt(0)))
	if err != nil {
		return nil, nil, err
	}
	// lower part
	IdB := data.Id(q.N, q.N).Tensor(B)
	M1, err := data.NewConstantMatrix(q.N * 3, IdVB.Cols(), big.NewInt(0)).JoinCols(IdB)
	if err != nil {
		return nil, nil, err
	}
	// together
	M, err := M0.JoinRows(M1)
	if err != nil {
		return nil, nil, err
	}

	pkIPE, skIPE, err := q.PartFHIPE.GenerateKeys(M)
	if err != nil {
		return nil, nil, err
	}

	pk := &QuadPubKey{Ua: Ua, VB: VB, PubIPE: pkIPE}
	sk := &QuadSecKey{U: U, V: V, SecIPE: skIPE}

	return pk, sk, nil
}

type QuadCipher struct {
	Cx data.VectorG1
	Cy data.VectorG2
	CIPE data.VectorG1
}

// Encrypt encrypts input vectors x and y with the
// master secret key msk. It returns the appropriate ciphertext.
// If ciphertext could not be generated, it returns an error.
func (q *Quad) Encrypt(x, y data.Vector, pubKey *QuadPubKey) (*QuadCipher, error) {
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
	fmt.Println(xIPE, pubKey.PubIPE)
	cIPE, err := q.PartFHIPE.Encrypt(xIPE, pubKey.PubIPE)
	if err != nil {
		return nil, err
	}
	fmt.Println(cIPE)

	return &QuadCipher{Cx:Cx, Cy:Cy, CIPE:cIPE}, nil
}

// DeriveKey derives the functional encryption key for the scheme.
// It returns an error if the key could not be derived.
func (q *Quad) DeriveKey(secKey *QuadSecKey, F data.Matrix) (data.VectorG2, error) {
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
	//fmt.Println(FVvec)

	yIPE := append(UTFvec, FVvec...)
	//fmt.Println(yIPE)
	feKey, err := q.PartFHIPE.DeriveKey(yIPE, secKey.SecIPE)

	return feKey, err
}

// Decrypt decrypts the ciphertext c with the derived functional
// encryption key key in order to obtain function x^T * F * y.
func (q *Quad) Decrypt(c *QuadCipher, feKey data.VectorG2, F data.Matrix) (*big.Int, error) {
	fmt.Println(c.CIPE, feKey)
	d := q.PartFHIPE.PartDecrypt(c.CIPE, feKey)

	FCy, err := F.MatMulVecG2(c.Cy)
	if err != nil {
		return nil, err
	}

	v := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < q.N; i++ {
		pairedI := bn256.Pair(c.Cx[i], FCy[i])
		v = new(bn256.GT).Add(pairedI, v)
	}
	d = new(bn256.GT).Neg(d)
	v = new(bn256.GT).Add(v, d)

	// todo bound
	calc := dlog.NewCalc().InBN256().WithNeg()

	//fmt.Println("dec", dec, new(bn256.GT).ScalarBaseMult(big.NewInt(0)))
	res, err := calc.BabyStepGiantStep(v, new(bn256.GT).ScalarBaseMult(big.NewInt(1)))

	return res, err
}
