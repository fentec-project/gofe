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

package abe

import (
	"math/big"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/bn256"
	"strconv"
	"fmt"
)

// DIPPE represents a DIPPE scheme.
type DIPPE struct {
	AsumpSize int
	G1ToA data.MatrixG1
	G1ToUA data.MatrixG1
	P *big.Int // order of the elliptic curve
}

// DIPPEPubKey represents a public key of an authority in DIPPE scheme.
type DIPPEPubKey struct {
	G1ToWtA data.MatrixG1
	GToAlphaA data.VectorGT
	G2ToSigma *bn256.G2
}

// DIPPESecKey represents a secret key of an authority in DIPPE scheme.
type DIPPESecKey struct {
	Sigma *big.Int
	W data.Matrix
	Alpha data.Vector
}

// DIPPEAuth represents an authority in DIPPE scheme
type DIPPEAuth struct {
	Id int
	Sk DIPPESecKey
	Pk DIPPEPubKey
}

// DIPPEAuth represents an authority in DIPPE scheme
type DIPPECipher struct {
	C0 data.VectorG1
	C data.MatrixG1
	CPrime *bn256.GT
}

// NewFAME configures a new instance of the scheme.
func NewDIPPE(assumpSize int) (*DIPPE, error) {
	sampler := sample.NewUniform(bn256.Order)
	//sampler := sample.NewUniformRange(big.NewInt(1), big.NewInt(2))

	A, err := data.NewRandomMatrix(assumpSize + 1, assumpSize, sampler)
	if err != nil {
		return nil, err
	}
	g1ToA := A.MulG1()

	U, err := data.NewRandomMatrix(assumpSize + 1, assumpSize + 1, sampler)
	if err != nil {
		return nil, err
	}
	UA, err := U.Mul(A)
	if err != nil {
		return nil, err
	}
	UA.Mod(bn256.Order)
	g1ToUA := UA.MulG1()

	return &DIPPE{AsumpSize:assumpSize,
				  G1ToA:     g1ToA,
				  G1ToUA:    g1ToUA,
				  P: 		 bn256.Order,}, nil
}

func (d *DIPPE) NewDIPPEAuth(id int) (*DIPPEAuth, error) {
	sampler := sample.NewUniform(bn256.Order)
	//sampler := sample.NewUniformRange(big.NewInt(1), big.NewInt(2))

	W, err := data.NewRandomMatrix(d.AsumpSize + 1, d.AsumpSize + 1, sampler)
	if err != nil {
		return nil, err
	}

	alpha, err := data.NewRandomVector(d.AsumpSize + 1, sampler)
	if err != nil {
		return nil, err
	}

	sigma, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	sk := DIPPESecKey{W: W, Alpha: alpha, Sigma: sigma}

	g1ToWtA, err := W.Transpose().MatMulMatG1(d.G1ToA)
	if err != nil {
		return nil, err
	}

	alphaAsMatrix := data.Matrix([]data.Vector{alpha})
	g1ToAlphaA, err := alphaAsMatrix.MatMulMatG1(d.G1ToA)
	if err != nil {
		return nil, err
	}

	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	gtToAlphaA := data.VectorGT(make([]*bn256.GT, d.AsumpSize))
	for i := 0; i < d.AsumpSize; i++ {
		gtToAlphaA[i] = bn256.Pair(g1ToAlphaA[0][i], g2)
	}

	g2ToSigma := new(bn256.G2).ScalarMult(g2, sigma)

	pk := DIPPEPubKey{G1ToWtA:g1ToWtA, GToAlphaA:gtToAlphaA, G2ToSigma:g2ToSigma}
	fmt.Println(sk, pk)
	return &DIPPEAuth{Id:id, Sk:sk, Pk:pk}, nil
}

func (d *DIPPE) Encrypt(m *bn256.GT, x data.Vector, pubKeys []*DIPPEPubKey) (*DIPPECipher, error) {
	sampler := sample.NewUniform(bn256.Order)
	//sampler := sample.NewUniformRange(big.NewInt(1), big.NewInt(2))

	s, err := data.NewRandomVector(d.AsumpSize, sampler)
	if err != nil {
		return nil, err
	}

	c0 := d.G1ToA.MulVector(s)
	if err != nil {
		return nil, err
	}

	c := make(data.MatrixG1, len(x))
	for i := range x {
		g1ToXiUA := d.G1ToUA.MulScalar(x[i])
		g1ToXiUplusWtiA := g1ToXiUA.Add(pubKeys[i].G1ToWtA)
		c[i] = g1ToXiUplusWtiA.MulVector(s)
	}

	cPrime := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for _, e := range pubKeys {
		tmp := e.GToAlphaA.Dot(s)
		cPrime.Add(tmp, cPrime)
	}
	cPrime.Add(m, cPrime)

	fmt.Println("cprime", cPrime)
	fmt.Println("c", c)

	return &DIPPECipher{C0:c0, C:c, CPrime:cPrime}, nil
}

func (a *DIPPEAuth) Keygen(v data.Vector, pubKeys []*DIPPEPubKey, gid string) (data.VectorG2, error) {
	g2ToMu := make(data.VectorG2, a.Sk.W.Rows())
	for i:=0; i< a.Sk.W.Rows(); i++ {
		g2ToMu[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	var err error
	fmt.Println("len", len(pubKeys))
	for j:=0; j<len(pubKeys); j++ {
		if j == a.Id {
			continue
		}
		yToSigma := new(bn256.G2).ScalarMult(pubKeys[j].G2ToSigma, a.Sk.Sigma)
		//fmt.Println(j, a.Id, yToSigma)
		for i:=0; i< a.Sk.W.Rows(); i++ {
			hashed, err := bn256.HashG2(strconv.Itoa(i) + yToSigma.String() + gid + v.String())

			//fmt.Println("hashed", i, hashed)
			//hashed.ScalarBaseMult(big.NewInt(1))
			if err != nil {
				return nil, err
			}
			fmt.Println("hashed", hashed)

			if j > a.Id {
				fmt.Println("here")
				//negHashed := new(bn256.G2).Neg(hashed)
				//fmt.Println(negHashed)
				//fmt.Println(hashed)
				hashed = new(bn256.G2).Neg(hashed)
			}
			//fmt.Println("hashed", hashed)
			g2ToMu[i] = new(bn256.G2).Add(g2ToMu[i], hashed)
			fmt.Println("g2to", i, g2ToMu[i])
		}
	}
	fmt.Println("g2ToMu", g2ToMu)
	//negg2tomu := g2ToMu.Neg()
	//fmt.Println("g2ToMu", negg2tomu)

	g2ToH := make(data.VectorG2, a.Sk.W.Rows())
	for j := range g2ToH {
		g2ToH[j], err = bn256.HashG2(strconv.Itoa(j) + gid + v.String())
		//g2ToH[j].ScalarBaseMult(big.NewInt(0))

		if err != nil {
			return nil, err
		}
	}
	g2ToWH, err := a.Sk.W.MatMulVecG2(g2ToH)
	if err != nil {
		return nil, err
	}
	g2ToViWH := g2ToWH.MulScalar(v[a.Id]).Neg()

	g2ToAlpha := a.Sk.Alpha.MulG2()

	ret := g2ToAlpha.Add(g2ToViWH).Add(g2ToMu)

	//fmt.Println("key", ret)

	return ret, nil
}

func (d *DIPPE) Decrypt(c *DIPPECipher, keys data.MatrixG2, v data.Vector, gid string) (*bn256.GT, error) {
	gTToAlphaAS := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	ones := data.NewConstantMatrix(1, keys.Rows(), big.NewInt(1))
	kSum, err := ones.MatMulMatG2(keys)
	if err != nil {
		return nil, err
	}
	fmt.Println("ksum", kSum)
	for i, e:= range c.C0 {
		tmpGT := bn256.Pair(e, kSum[0][i])
		gTToAlphaAS.Add(gTToAlphaAS, tmpGT)
	}

	vMat := make(data.Matrix, 1)
	vMat[0] = v
	cSum, err := vMat.MatMulMatG1(c.C)
	if err != nil {
		return nil, err
	}

	//fmt.Println(c.C.Cols(), len(v))
	for j := range cSum[0] {
		hashed, err := bn256.HashG2(strconv.Itoa(j) + gid + v.String())
		//hashed.ScalarBaseMult(big.NewInt(0))

		if err != nil {
			return nil, err
		}
		tmpGT := bn256.Pair(cSum[0][j], hashed)
		gTToAlphaAS.Add(gTToAlphaAS, tmpGT)
	}
	gTToAlphaAS.Neg(gTToAlphaAS)

	return new(bn256.GT).Add(c.CPrime, gTToAlphaAS), nil
}