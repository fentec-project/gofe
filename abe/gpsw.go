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
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// This is a key policy (KP) attribute based (ABE) scheme based on
// Goyal, Pandey, Sahai, Waters:
// "Attribute-Based Encryption for Fine-Grained Access Control of
// Encrypted Data"
//
// We abbreviated it GPSW scheme to honor the authors. This scheme
// enables distribution of keys based on a boolean expression
// determining which attributes are needed for an entity to be able
// to decrypt. Each key is connected to some attribute, such that
// only a set of keys whose attributes are sufficient can decrypt
// the massage.
// This scheme is a PUBLIC-KEY scheme - no master secret key is needed
// to encrypt the messages.
//

// GSPWParams represents configuration parameters for the GSPW ABE-scheme instance.
type GSPWParams struct {
	L int      // number of attributes
	P *big.Int // order of the elliptic curve
}

// GSPW represents an GSPW ABE-scheme.
type GSPW struct {
	Params *GSPWParams
}

// NewGSPW configures a new instance of the scheme.
// It accepts l the number of attributes possibly used in
// the scheme. Attributes' names will be considered as
// elements of a set {0, 1,..., l-1}.
func NewGSPW(l int) *GSPW {
	return &GSPW{Params: &GSPWParams{
		L: l, // number of attributes in the whole universe
		P: bn256.Order,  // the order of the pairing groups
	}}
}

// GSPWPubKey represents a public key of the GSPW ABE-scheme.
type GSPWPubKey struct {
	t data.VectorG2
	y *bn256.GT
}

// GenerateMasterKeys generates a new set of public keys, needed
// for encrypting data, and secret keys needed for generating keys
// for decryption.
func (a *GSPW) GenerateMasterKeys() (*GSPWPubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.P)
	sk, err := data.NewRandomVector(a.Params.L+1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk[:a.Params.L].MulG2()
	y := new(bn256.GT).ScalarBaseMult(sk[a.Params.L])

	return &GSPWPubKey{t: t, y: y}, sk, nil
}

// GSPWCipher represents a ciphertext of the GSPW ABE-scheme.
type GSPWCipher struct {
	gamma     []int         // the set of attributes that can be used for policy of decryption
	attribToI map[int]int   // a map that connects the attributes in gamma with elements of e
	e0        *bn256.GT     // the first part of the encryption
	e         data.VectorG2 // the second part of the encryption
}

// Encrypt takes as an input a message msg represented as an element of pairing
// group G_T, gamma a set of attributes that can be latter used to in the decryption policy
// and a public key pk. It returns an encryption of msk. In case of a failed procedure
// an error is returned.
func (a *GSPW) Encrypt(msg *bn256.GT, gamma []int, pk *GSPWPubKey) (*GSPWCipher, error) {
	sampler := sample.NewUniform(a.Params.P)
	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	e0 := new(bn256.GT).Add(msg, new(bn256.GT).ScalarMult(pk.y, s))
	e := make(data.VectorG2, len(gamma))
	attribToI := make(map[int]int)
	for i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.t[el], s)
		attribToI[el] = i
	}

	return &GSPWCipher{gamma: gamma,
		attribToI: attribToI,
		e0:        e0,
		e:         e}, nil
}

// GeneratePolicyKeys given a monotone span program (MSP) msp and the vector of secret
// keys produces a vector of keys needed for the decryption. In particular,
// for each row of the MSP matrix msp.mat it creates a corresponding key. Since
// each row of msp.mat has a corresponding key, this keys can be latter delegated
// to entities with corresponding attributes.
func (a *GSPW) GeneratePolicyKeys(msp *MSP, sk data.Vector) (data.VectorG1, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	if len(sk) != (a.Params.L + 1) {
		return nil, fmt.Errorf("the secret key has wrong length")
	}

	u, err := getSum(sk[a.Params.L], a.Params.P, len(msp.Mat[0]))
	if err != nil {
		return nil, err
	}

	key := make(data.VectorG1, len(msp.Mat))
	for i := 0; i < len(msp.Mat); i++ {
		if 0 > msp.RowToAttrib[i] || a.Params.L <= msp.RowToAttrib[i] {
			return nil, fmt.Errorf("attributes of msp not in the universe of a")
		}

		tMapIInv := new(big.Int).ModInverse(sk[msp.RowToAttrib[i]], a.Params.P)
		matTimesU, err := msp.Mat[i].Dot(u)
		if err != nil {
			return nil, err
		}
		pow := new(big.Int).Mul(tMapIInv, matTimesU)
		pow.Mod(pow, a.Params.P)
		key[i] = new(bn256.G1).ScalarBaseMult(pow)
	}

	return key, nil
}

// getSum is a helping function that given integers y, p and d generates a
// random d dimensional vector over Z_p whose entries sum to y in Z_p.
func getSum(y *big.Int, p *big.Int, d int) (data.Vector, error) {
	sampler := sample.NewUniform(p)
	ret, err := data.NewRandomVector(d, sampler)
	if err != nil {
		return nil, err
	}
	sum := big.NewInt(0)
	for i := 0; i < d-1; i++ {
		sum.Add(sum, ret[i])
		sum.Mod(sum, p)
	}
	ret[d-1] = new(big.Int).Sub(y, sum)
	ret[d-1].Mod(ret[d-1], p)

	return ret, nil
}

// GSPWKey represents a key structure for decrypting a ciphertext. It includes
// mat a matrix, d a set of vectors and rowToAttib a mapping from rows of mat
// (or entries of d) to corresponding attributes. Vector d is a set of keys
// that can decrypt a ciphertext of the rows of mat span the vector [1, 1,..., 1].
type GSPWKey struct {
	mat         data.Matrix
	d           data.VectorG1
	rowToAttrib []int
}

// DelegateKeys given the set of all keys produced from the MSP struct msp joins
// those that correspond to attributes appearing in attrib and creates an GSPWKey
// for the decryption.
func (a *GSPW) DelegateKeys(keys data.VectorG1, msp *MSP, attrib []int) *GSPWKey {
	attribMap := make(map[int]bool)
	for _, e := range attrib {
		attribMap[e] = true
	}
	mat := make([]data.Vector, 0)
	d := make(data.VectorG1, 0)
	rowToAttrib := make([]int, 0)
	for i := 0; i < len(msp.Mat); i++ {
		if attribMap[msp.RowToAttrib[i]] {
			mat = append(mat, msp.Mat[i])
			d = append(d, keys[i])
			rowToAttrib = append(rowToAttrib, msp.RowToAttrib[i])
		}
	}

	return &GSPWKey{mat: mat,
		d:           d,
		rowToAttrib: rowToAttrib}
}

// Decrypt takes as an input a cipher and an GSPWKey key and tries to decrypt
// the cipher. If the GSPWKey is properly generated, this is possible if and only
// if the rows of the matrix in the key span the vector [1, 1,..., 1]. If this
// is not possible, an error is returned.
func (a *GSPW) Decrypt(cipher *GSPWCipher, key *GSPWKey) (*bn256.GT, error) {
	// get a combination alpha of keys needed to decrypt
	ones := data.NewConstantVector(len(key.mat[0]), big.NewInt(1))
	alpha, err := gaussianElimination(key.mat.Transpose(), ones, a.Params.P)
	if err != nil {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}

	ret := new(bn256.GT).Set(cipher.e0)
	for i := 0; i < len(alpha); i++ {
		pair := bn256.Pair(key.d[i], cipher.e[cipher.attribToI[key.rowToAttrib[i]]])
		pair.ScalarMult(pair, alpha[i])
		pair.Neg(pair)
		ret.Add(ret, pair)
	}

	return ret, nil
}
