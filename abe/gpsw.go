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

	"io"

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

// GPSWParams represents configuration parameters for the GPSW ABE-scheme instance.
type GPSWParams struct {
	L int      // number of attributes
	P *big.Int // order of the elliptic curve
}

// GPSW represents an GPSW ABE-scheme.
type GPSW struct {
	Params *GPSWParams
}

// NewGPSW configures a new instance of the scheme.
// It accepts l the number of attributes possibly used in
// the scheme. Attributes' names will be considered as
// elements of a set {0, 1,..., l-1}.
func NewGPSW(l int) *GPSW {
	return &GPSW{Params: &GPSWParams{
		L: l,           // number of attributes in the whole universe
		P: bn256.Order, // the order of the pairing groups
	}}
}

// GPSWPubKey represents a public key of the GPSW ABE-scheme.
type GPSWPubKey struct {
	T data.VectorG2
	Y *bn256.GT
}

// GenerateMasterKeys generates a new set of public keys, needed
// for encrypting data, and secret keys needed for generating keys
// for decryption.
func (a *GPSW) GenerateMasterKeys() (*GPSWPubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.P)
	sk, err := data.NewRandomVector(a.Params.L+1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk[:a.Params.L].MulG2()
	y := new(bn256.GT).ScalarBaseMult(sk[a.Params.L])

	return &GPSWPubKey{T: t, Y: y}, sk, nil
}

// GPSWCipher represents a ciphertext of the GPSW ABE-scheme.
type GPSWCipher struct {
	Gamma     []int         // the set of attributes that can be used for policy of decryption
	AttribToI map[int]int   // a map that connects the attributes in gamma with elements of e
	E0        *bn256.GT     // the first part of the encryption
	E         data.VectorG2 // the second part of the encryption
	SymEnc    []byte        // symmetric encryption of the message
	Iv        []byte        // initialization vector for symmetric encryption
}

// Encrypt takes as an input a message msg given as a string, gamma a set of
// attributes that can be latter used in a decryption policy and a public
// key pk. It returns an encryption of msg. In case of a failed procedure an
// error is returned.
func (a *GPSW) Encrypt(msg string, gamma []int, pk *GPSWPubKey) (*GPSWCipher, error) {
	// msg is encrypted using CBC, with a random key that is encapsulated
	// with GPSW
	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cbc.NewCBCEncrypter(c, iv)

	msgByte := []byte(msg)
	// message is padded according to pkcs7 standard
	padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)

	// encapsulate the key with GPSW
	sampler := sample.NewUniform(a.Params.P)
	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	e0 := new(bn256.GT).Add(keyGt, new(bn256.GT).ScalarMult(pk.Y, s))
	e := make(data.VectorG2, len(gamma))
	attribToI := make(map[int]int)
	for i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.T[el], s)
		attribToI[el] = i
	}

	return &GPSWCipher{Gamma: gamma,
		AttribToI: attribToI,
		E0:        e0,
		E:         e,
		SymEnc:    symEnc,
		Iv:        iv}, nil
}

// GeneratePolicyKeys given a monotone span program (MSP) msp and the vector of secret
// keys produces a vector of keys needed for the decryption. In particular,
// for each row of the MSP matrix msp.mat it creates a corresponding key. Since
// each row of msp.mat has a corresponding key, this keys can be latter delegated
// to entities with corresponding attributes.
func (a *GPSW) GeneratePolicyKeys(msp *MSP, sk data.Vector) (data.VectorG1, error) {
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

// GPSWKey represents a key structure for decrypting a ciphertext. It includes
// Mat a matrix, D a set of vectors and RowToAttib a mapping from rows of Mat
// (or entries of D) to corresponding attributes. Vector D is a set of keys
// that can decrypt a ciphertext of the rows of mat span the vector [1, 1,..., 1].
type GPSWKey struct {
	Mat         data.Matrix
	D           data.VectorG1
	RowToAttrib []int
}

// DelegateKeys given the set of all keys produced from the MSP struct msp joins
// those that correspond to attributes appearing in attrib and creates an GPSWKey
// for the decryption.
func (a *GPSW) DelegateKeys(keys data.VectorG1, msp *MSP, attrib []int) *GPSWKey {
	attribMap := make(map[int]bool)
	for _, e := range attrib {
		attribMap[e] = true
	}

	countAttrib := 0
	for i := 0; i < len(msp.Mat); i++ {
		if attribMap[msp.RowToAttrib[i]] {
			countAttrib++
		}
	}

	mat := make([]data.Vector, countAttrib)
	d := make(data.VectorG1, countAttrib)
	rowToAttrib := make([]int, countAttrib)
	countAttrib = 0
	for i := 0; i < len(msp.Mat); i++ {
		if attribMap[msp.RowToAttrib[i]] {
			mat[countAttrib] = msp.Mat[i]
			d[countAttrib] = keys[i]
			rowToAttrib[countAttrib] = msp.RowToAttrib[i]
			countAttrib++
		}
	}

	return &GPSWKey{Mat: mat,
		D:           d,
		RowToAttrib: rowToAttrib}
}

// Decrypt takes as an input a cipher and an GPSWKey key and tries to decrypt
// the cipher. If the GPSWKey is properly generated, this is possible if and only
// if the rows of the matrix in the key span the vector [1, 1,..., 1]. If this
// is not possible, an error is returned.
func (a *GPSW) Decrypt(cipher *GPSWCipher, key *GPSWKey) (string, error) {
	// get a combination alpha of keys needed to decrypt
	ones := data.NewConstantVector(len(key.Mat[0]), big.NewInt(1))
	alpha, err := data.GaussianEliminationSolver(key.Mat.Transpose(), ones, a.Params.P)
	if err != nil {
		return "", fmt.Errorf("the provided key is not sufficient for the decryption")
	}

	// get a CBC key needed for the decryption of msg
	keyGt := new(bn256.GT).Set(cipher.E0)
	for i := 0; i < len(alpha); i++ {
		pair := bn256.Pair(key.D[i], cipher.E[cipher.AttribToI[key.RowToAttrib[i]]])
		pair.ScalarMult(pair, alpha[i])
		pair.Neg(pair)
		keyGt.Add(keyGt, pair)
	}

	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return "", err
	}

	msgPad := make([]byte, len(cipher.SymEnc))
	decrypter := cbc.NewCBCDecrypter(c, cipher.Iv)
	decrypter.CryptBlocks(msgPad, cipher.SymEnc)

	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return "", fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]

	return string(msgByte), nil
}
