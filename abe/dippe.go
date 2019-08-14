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
	g1ToUA := UA.MulG1()

	return &DIPPE{AsumpSize:assumpSize,
				  G1ToA:     g1ToA,
				  G1ToUA:    g1ToUA,
				  P: 		 bn256.Order,}, nil
}

func (d *DIPPE) NewDIPPEAuth() (*DIPPEAuth, error) {
	sampler := sample.NewUniform(bn256.Order)
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

	return &DIPPEAuth{Sk:sk, Pk:pk}, nil
}

func (d *DIPPE) Encrypt(m *bn256.GT, x data.Vector, pubKeys []DIPPEPubKey) (*DIPPECipher, error) {
	sampler := sample.NewUniform(bn256.Order)
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
		cPrime.Add(cPrime, tmp)
	}

	return &DIPPECipher{C0:c0, C:c, CPrime:cPrime}, nil
}
