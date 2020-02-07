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
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strconv"

	"io"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// DIPPE represents a Decentralized Inner-Product Predicate Encryption
// (DIPPE) scheme introduced by Y. Michalevsky and M. Joye in:
// "Decentralized Policy-Hiding Attribute-Based Encryption with Receiver Privacy"
// https://eprint.iacr.org/2018/753.pdf
type DIPPE struct {
	secLevel int
	G1ToA    data.MatrixG1
	G1ToUA   data.MatrixG1
	P        *big.Int // order of the elliptic curve
}

// DIPPEPubKey represents a public key of an authority in DIPPE scheme.
type DIPPEPubKey struct {
	G1ToWtA   data.MatrixG1
	GToAlphaA data.VectorGT
	G2ToSigma *bn256.G2
}

// DIPPESecKey represents a secret key of an authority in DIPPE scheme.
type DIPPESecKey struct {
	Sigma *big.Int
	W     data.Matrix
	Alpha data.Vector
}

// DIPPEAuth represents an authority in DIPPE scheme
type DIPPEAuth struct {
	ID int
	Sk DIPPESecKey
	Pk DIPPEPubKey
}

// DIPPECipher represents a ciphertext in DIPPE scheme
type DIPPECipher struct {
	C0     data.VectorG1
	C      data.MatrixG1
	CPrime *bn256.GT
	X      data.Vector // policy vector
	SymEnc []byte      // symmetric encryption of the message
	Iv     []byte      // initialization vector for symmetric encryption
}

// NewDIPPE configures a new instance of the scheme. The input parameter
// defines the security assumption of the scheme, so called k-Lin assumption,
// where k is the input.
func NewDIPPE(secLevel int) (*DIPPE, error) {
	sampler := sample.NewUniform(bn256.Order)

	A, err := data.NewRandomMatrix(secLevel+1, secLevel, sampler)
	if err != nil {
		return nil, err
	}
	g1ToA := A.MulG1()

	U, err := data.NewRandomMatrix(secLevel+1, secLevel+1, sampler)
	if err != nil {
		return nil, err
	}
	UA, err := U.Mul(A)
	if err != nil {
		return nil, err
	}
	UA.Mod(bn256.Order)
	g1ToUA := UA.MulG1()

	return &DIPPE{secLevel: secLevel,
		G1ToA:  g1ToA,
		G1ToUA: g1ToUA,
		P:      bn256.Order}, nil
}

// NewDIPPEAuth configures a new authority that will be able to
// produce decryption keys. If the scheme will have n authorities
// it is assumed that each will have a different id from [0, n).
func (d *DIPPE) NewDIPPEAuth(id int) (*DIPPEAuth, error) {
	sampler := sample.NewUniform(bn256.Order)

	W, err := data.NewRandomMatrix(d.secLevel+1, d.secLevel+1, sampler)
	if err != nil {
		return nil, err
	}

	alpha, err := data.NewRandomVector(d.secLevel+1, sampler)
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
	gtToAlphaA := make(data.VectorGT, d.secLevel)
	for i := 0; i < d.secLevel; i++ {
		gtToAlphaA[i] = bn256.Pair(g1ToAlphaA[0][i], g2)
	}

	g2ToSigma := new(bn256.G2).ScalarMult(g2, sigma)

	pk := DIPPEPubKey{G1ToWtA: g1ToWtA, GToAlphaA: gtToAlphaA, G2ToSigma: g2ToSigma}

	return &DIPPEAuth{ID: id, Sk: sk, Pk: pk}, nil
}

// Encrypt takes as an input a string message msg, a vector x representing a
// decryption policy and a slice of public keys of the participating authorities.
// The i-th coordinate of x corresponds to i-th public key of the authority with
// id i. It returns an encryption of msg. In case of a failed procedure an
// error is returned.
func (d *DIPPE) Encrypt(msg string, x data.Vector, pubKeys []*DIPPEPubKey) (*DIPPECipher, error) {
	// msg is encrypted using CBC, with a random key that is encapsulated
	// with DIPPE
	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	a, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, a.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cbc.NewCBCEncrypter(a, iv)

	msgByte := []byte(msg)
	// message is padded according to pkcs7 standard
	padLen := a.BlockSize() - (len(msgByte) % a.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)

	// encapsulate the key with DIPPE
	sampler := sample.NewUniform(bn256.Order)
	s, err := data.NewRandomVector(d.secLevel, sampler)
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
	cPrime.Add(keyGt, cPrime)

	return &DIPPECipher{C0: c0, C: c, CPrime: cPrime, X: x.Copy(), SymEnc: symEnc, Iv: iv}, nil
}

// DeriveKeyShare allows an authority to give a partial decryption key. Collecting all
// such partial keys allows a user to decrypt the message. The input vector v contains
// an information about the user that will allow him to decrypt iff the inner product
// v times x = 0 for the policy x. GID is a global identifier of the user and a slice of
// public keys of the authorities should be given.
func (a *DIPPEAuth) DeriveKeyShare(v data.Vector, pubKeys []*DIPPEPubKey, gid string) (data.VectorG2, error) {
	g2ToMu := make(data.VectorG2, a.Sk.W.Rows())
	for i := 0; i < a.Sk.W.Rows(); i++ {
		g2ToMu[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	g2ToAlpha := a.Sk.Alpha.MulG2()

	var err error
	for j := 0; j < len(pubKeys); j++ {
		if j == a.ID {
			continue
		}

		yToSigma := new(bn256.G2).ScalarMult(pubKeys[j].G2ToSigma, a.Sk.Sigma)
		for i := 0; i < a.Sk.W.Rows(); i++ {
			hashed, err := bn256.HashG2(strconv.Itoa(i) + yToSigma.String() + gid + v.String())
			if err != nil {
				return nil, err
			}

			if j > a.ID {
				hashed.Neg(hashed)
			}
			g2ToMu[i] = g2ToMu[i].Add(hashed, g2ToMu[i])
		}
	}

	g2ToH := make(data.VectorG2, a.Sk.W.Rows())
	for j := range g2ToH {
		g2ToH[j], err = bn256.HashG2(strconv.Itoa(j) + gid + v.String())

		if err != nil {
			return nil, err
		}
	}
	g2ToWH, err := a.Sk.W.MatMulVecG2(g2ToH)
	if err != nil {
		return nil, err
	}
	g2ToViWH := g2ToWH.MulScalar(v[a.ID]).Neg()

	return g2ToAlpha.Add(g2ToViWH).Add(g2ToMu), nil
}

// Decrypt accepts the ciphertext, a slice of keys obtained from the authorities,
// a vector v representing the users decryption allowance, and a global identifier.
// If the provided keys are correct and the inner product v times x = 0 for the policy
// x, the message is decrypted, otherwise an error is returned.
func (d *DIPPE) Decrypt(cipher *DIPPECipher, keys []data.VectorG2, v data.Vector, gid string) (string, error) {
	// check if the decryption is possible
	prod, err := v.Dot(cipher.X)
	if err != nil {
		return "", err
	}

	if prod.Sign() != 0 {
		return "", fmt.Errorf("insufficient keys")
	}

	// use DIPPE decryption procedure to get a CBC key
	// needed for the decryption of the message
	gTToAlphaAS := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	ones := data.NewConstantMatrix(1, len(keys), big.NewInt(1))
	sum, err := ones.MatMulMatG2(data.MatrixG2(keys))
	if err != nil {
		return "", err
	}

	for i, e := range cipher.C0 {
		tmpGT := bn256.Pair(e, sum[0][i])
		gTToAlphaAS.Add(gTToAlphaAS, tmpGT)
	}

	vMat := make(data.Matrix, 1)
	vMat[0] = v
	cSum, err := vMat.MatMulMatG1(cipher.C)
	if err != nil {
		return "", err
	}

	for j := range cSum[0] {
		hashed, err := bn256.HashG2(strconv.Itoa(j) + gid + v.String())
		if err != nil {
			return "", err
		}

		tmpGT := bn256.Pair(cSum[0][j], hashed)
		gTToAlphaAS.Add(gTToAlphaAS, tmpGT)
	}
	gTToAlphaAS.Neg(gTToAlphaAS)

	keyGt := new(bn256.GT).Add(cipher.CPrime, gTToAlphaAS)

	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	a, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return "", err
	}

	msgPad := make([]byte, len(cipher.SymEnc))
	decrypter := cbc.NewCBCDecrypter(a, cipher.Iv)
	decrypter.CryptBlocks(msgPad, cipher.SymEnc)

	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return "", fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]

	return string(msgByte), nil
}

// ExactThresholdPolicyVecInit is used for the transformation of the DIPPE
// scheme into an ABE scheme with an exact threshold. In particular given a
// slice of attributes, a threshold value and the number of all possible
// attributes it creates a policy vector that can be used for the DIPPE encryption.
// The user will be able to decrypt only if he posses exactly the threshold
// value of the attributes.
func (d DIPPE) ExactThresholdPolicyVecInit(attrib []int, threshold int, numAttrib int) (data.Vector, error) {
	policyVec := data.NewConstantVector(numAttrib+1, big.NewInt(0))
	one := big.NewInt(1)
	for _, e := range attrib {
		if e > numAttrib {
			return nil, fmt.Errorf("attributes out of range")
		}
		policyVec[e].Set(one)
	}
	policyVec[numAttrib].Set(big.NewInt(int64(-threshold)))

	return policyVec, nil
}

// ConjunctionPolicyVecInit is used for the transformation of the DIPPE
// scheme into an ABE scheme with conjugation policy. In particular given a
// slice of attributes and the number of all possible attributes it creates
// a policy vector that can be used for the DIPPE encryption. The user will
// be able to decrypt only if he posses all the demanded attributes.
func (d DIPPE) ConjunctionPolicyVecInit(attrib []int, numAttrib int) (data.Vector, error) {
	policyVec := data.NewConstantVector(numAttrib+1, big.NewInt(0))
	sampler := sample.NewUniform(bn256.Order)
	last := big.NewInt(0)
	for _, e := range attrib {
		if e > numAttrib {
			return nil, fmt.Errorf("attributes out of range")
		}
		tmp, err := sampler.Sample()
		if err != nil {
			return nil, err
		}
		policyVec[e].Set(tmp)
		last.Sub(last, tmp)
	}
	policyVec[numAttrib].Set(last)

	return policyVec, nil
}

// AttributeVecInit given the attributes and the number of all possible
// attributes creates a vector describing the users allowance. The function is
// needed in the the transformation of the DIPPE scheme into an ABE scheme
// with threshold or conjugation.
func (d DIPPE) AttributeVecInit(attrib []int, numAttrib int) (data.Vector, error) {
	attribVec := data.NewConstantVector(numAttrib+1, big.NewInt(0))
	one := big.NewInt(1)
	for _, e := range attrib {
		if e > numAttrib {
			return nil, fmt.Errorf("attributes out of range")
		}
		attribVec[e].Set(one)
	}
	attribVec[numAttrib].Set(one)

	return attribVec, nil
}
