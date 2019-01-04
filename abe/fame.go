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

	"fmt"
	"strconv"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// This is a ciphertext policy (CP) attribute based (ABE) scheme based
// on Shashank Agrawal, Melissa Chase:
// "FAME: Fast Attribute-based Message Encryption"
//
// This scheme enables encryption based on a boolean expression
// determining which attributes are needed for an entity to be able
// to decrypt. Moreover, secret keys are generated, where each key
// is connected to some attribute, such that only a set of keys whose
// attributes are sufficient can decrypt the massage.
// This scheme is a PUBLIC-KEY scheme - no master secret key is needed
// to encrypt the messages.
//

// FAME represents a FAME scheme.
type FAME struct {
	P *big.Int // order of the elliptic curve
}

// NewFAME configures a new instance of the scheme.
func NewFAME() *FAME {
	return &FAME{P: bn256.Order}
}

// FAMESecKey represents a master secret key of a FAME scheme.
type FAMESecKey struct {
	partInt [4]*big.Int
	partG1  [3]*bn256.G1
}

// FAMEPubKey represents a public key of a FAME scheme.
type FAMEPubKey struct {
	partG2 [2]*bn256.G2
	partGT [2]*bn256.GT
}

// GenerateMasterKeys generates a new set of public keys, needed
// for encrypting data, and master secret keys needed for generating
// keys for decrypting.
func (a *FAME) GenerateMasterKeys() (*FAMEPubKey, *FAMESecKey, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), a.P)
	val, err := data.NewRandomVector(7, sampler)
	if err != nil {
		return nil, nil, err
	}

	partInt := [4]*big.Int{val[0], val[1], val[2], val[3]}
	partG1 := [3]*bn256.G1{new(bn256.G1).ScalarBaseMult(val[4]),
		new(bn256.G1).ScalarBaseMult(val[5]),
		new(bn256.G1).ScalarBaseMult(val[6])}
	partG2 := [2]*bn256.G2{new(bn256.G2).ScalarBaseMult(val[0]),
		new(bn256.G2).ScalarBaseMult(val[1])}
	tmp1 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(val[0], val[4]), val[6]), a.P)
	tmp2 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(val[1], val[5]), val[6]), a.P)
	partGT := [2]*bn256.GT{new(bn256.GT).ScalarBaseMult(tmp1),
		new(bn256.GT).ScalarBaseMult(tmp2)}

	return &FAMEPubKey{partG2: partG2, partGT: partGT},
		&FAMESecKey{partInt: partInt, partG1: partG1}, nil
}

// FAMECipher represents a ciphertext of a FAME scheme.
type FAMECipher struct {
	ct0     [3]*bn256.G2
	ct      [][3]*bn256.G1
	ctPrime *bn256.GT
	msp     *MSP
}

// Encrypt takes as an input a message msg represented as an element of an elliptic
// curve, a MSP struct representing the decryption policy, and a public key pk. It
// returns an encryption of the message. In case of a failed procedure an error
// is returned.
func (a *FAME) Encrypt(msg *bn256.GT, msp *MSP, pk *FAMEPubKey) (*FAMECipher, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}

	sampler := sample.NewUniform(a.P)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, err
	}
	ct0 := [3]*bn256.G2{new(bn256.G2).ScalarMult(pk.partG2[0], s[0]),
		new(bn256.G2).ScalarMult(pk.partG2[1], s[1]),
		new(bn256.G2).ScalarBaseMult(new(big.Int).Add(s[0], s[1]))}

	ct := make([][3]*bn256.G1, len(msp.Mat))
	for i := 0; i < len(msp.Mat); i++ {
		for l := 0; l < 3; l++ {
			hs1, err := bn256.HashG1(strconv.Itoa(msp.RowToAttrib[i]) + " " + strconv.Itoa(l) + " 0")
			if err != nil {
				return nil, err
			}
			hs1.ScalarMult(hs1, s[0])

			hs2, err := bn256.HashG1(strconv.Itoa(msp.RowToAttrib[i]) + " " + strconv.Itoa(l) + " 1")
			if err != nil {
				return nil, err
			}
			hs2.ScalarMult(hs2, s[1])

			ct[i][l] = new(bn256.G1).Add(hs1, hs2)
			for j := 0; j < len(msp.Mat[0]); j++ {
				hs1, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 0")
				if err != nil {
					return nil, err
				}
				hs1.ScalarMult(hs1, s[0])

				hs2, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 1")
				if err != nil {
					return nil, err
				}
				hs2.ScalarMult(hs2, s[1])

				hsToM := new(bn256.G1).Add(hs1, hs2)
				pow := new(big.Int).Set(msp.Mat[i][j])
				if pow.Sign() == -1 {
					pow.Neg(pow)
					hsToM.ScalarMult(hsToM, pow)
					hsToM.Neg(hsToM)
				} else {
					hsToM.ScalarMult(hsToM, pow)
				}
				ct[i][l].Add(ct[i][l], hsToM)
			}
		}
	}

	ctPrime := new(bn256.GT).ScalarMult(pk.partGT[0], s[0])
	ctPrime.Add(ctPrime, new(bn256.GT).ScalarMult(pk.partGT[1], s[1]))
	ctPrime.Add(ctPrime, msg)

	return &FAMECipher{ct0: ct0, ct: ct, ctPrime: ctPrime, msp: msp}, nil
}

// FAMEAttribKeys represents keys corresponding to attributes possessed by
// an entity and used for decrypting in a FAME scheme.
type FAMEAttribKeys struct {
	k0        [3]*bn256.G2
	k         [][3]*bn256.G1
	kPrime    [3]*bn256.G1
	attribToI map[int]int
}

// GenerateAttribKeys given a set of attributes gamma and the master secret key
// generates keys that can be used for the decryption of any ciphertext encoded
// with a policy for which attributes gamma are sufficient.
func (a *FAME) GenerateAttribKeys(gamma []int, sk *FAMESecKey) (*FAMEAttribKeys, error) {
	sampler := sample.NewUniform(a.P)
	r, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, err
	}
	sigma, err := data.NewRandomVector(len(gamma), sampler)
	if err != nil {
		return nil, err
	}

	pow0 := new(big.Int).Mul(sk.partInt[2], r[0])
	pow0.Mod(pow0, a.P)
	pow1 := new(big.Int).Mul(sk.partInt[3], r[1])
	pow1.Mod(pow1, a.P)
	pow2 := new(big.Int).Add(r[0], r[1])
	pow2.Mod(pow2, a.P)

	k0 := [3]*bn256.G2{new(bn256.G2).ScalarBaseMult(pow0),
		new(bn256.G2).ScalarBaseMult(pow1),
		new(bn256.G2).ScalarBaseMult(pow2)}

	a0Inv := new(big.Int).ModInverse(sk.partInt[0], a.P)
	a1Inv := new(big.Int).ModInverse(sk.partInt[1], a.P)
	aInv := [2]*big.Int{a0Inv, a1Inv}

	k := make([][3]*bn256.G1, len(gamma))
	attribToI := make(map[int]int)
	for i, y := range gamma {
		k[i] = [3]*bn256.G1{new(bn256.G1), new(bn256.G1), new(bn256.G1)}
		gSigma := new(bn256.G1).ScalarBaseMult(sigma[i])
		for t := 0; t < 2; t++ {
			hs0, err := bn256.HashG1(strconv.Itoa(y) + " 0 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}
			hs0.ScalarMult(hs0, pow0)
			hs1, err := bn256.HashG1(strconv.Itoa(y) + " 1 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}
			hs1.ScalarMult(hs1, pow1)
			hs2, err := bn256.HashG1(strconv.Itoa(y) + " 2 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}
			hs2.ScalarMult(hs2, pow2)

			k[i][t].Add(hs0, hs1)
			k[i][t].Add(k[i][t], hs2)
			k[i][t].Add(k[i][t], gSigma)
			k[i][t].ScalarMult(k[i][t], aInv[t])
		}

		k[i][2].ScalarBaseMult(sigma[i])
		k[i][2].Neg(k[i][2])

		attribToI[y] = i
	}

	sigmaPrime, err := sampler.Sample()
	if err != nil {
		return nil, err
	}
	gSigmaPrime := new(bn256.G1).ScalarBaseMult(sigmaPrime)

	kPrime := [3]*bn256.G1{new(bn256.G1), new(bn256.G1), new(bn256.G1)}
	for t := 0; t < 2; t++ {
		hs0, err := bn256.HashG1("0 0 0 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		hs0.ScalarMult(hs0, pow0)
		hs1, err := bn256.HashG1("0 0 1 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		hs1.ScalarMult(hs1, pow1)
		hs2, err := bn256.HashG1("0 0 2 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		hs2.ScalarMult(hs2, pow2)

		kPrime[t].Add(hs0, hs1)
		kPrime[t].Add(kPrime[t], hs2)
		kPrime[t].Add(kPrime[t], gSigmaPrime)
		kPrime[t].ScalarMult(kPrime[t], aInv[t])
		kPrime[t].Add(kPrime[t], sk.partG1[t])

	}
	kPrime[2].ScalarBaseMult(sigmaPrime)
	kPrime[2].Neg(kPrime[2])
	kPrime[2].Add(kPrime[2], sk.partG1[2])

	return &FAMEAttribKeys{k0: k0, k: k, kPrime: kPrime, attribToI: attribToI}, nil
}

// Decrypt takes as an input a cipher and an FAMEAttribKeys and tries to decrypt
// the cipher. This is possible only if the set of possessed attributes (and
// corresponding keys FAMEAttribKeys) suffices the encryption policy of the
// cipher. If this is not possible, an error is returned.
func (a *FAME) Decrypt(cipher *FAMECipher, key *FAMEAttribKeys, pk *FAMEPubKey) (*bn256.GT, error) {
	// find out which attributes are possessed
	attribMap := make(map[int]bool)
	for k := range key.attribToI {
		attribMap[k] = true
	}

	// create a matrix of needed keys
	preMatForKey := make([]data.Vector, 0)
	ctForKey := make([][3]*bn256.G1, 0)
	rowToAttrib := make([]int, 0)
	for i := 0; i < len(cipher.msp.Mat); i++ {
		if attribMap[cipher.msp.RowToAttrib[i]] {
			preMatForKey = append(preMatForKey, cipher.msp.Mat[i])
			ctForKey = append(ctForKey, cipher.ct[i])
			rowToAttrib = append(rowToAttrib, cipher.msp.RowToAttrib[i])
		}
	}

	matForKey, err := data.NewMatrix(preMatForKey)
	if err != nil {
		return nil, fmt.Errorf("the provided cipher is faulty")
	}

	// get a combination alpha of keys needed to decrypt
	oneVec := data.NewConstantVector(len(matForKey[0]), big.NewInt(0))
	oneVec[0].SetInt64(1)
	alpha, err := gaussianElimination(matForKey.Transpose(), oneVec, a.P)
	if err != nil {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}

	ret := new(bn256.GT).Set(cipher.ctPrime)

	ctProd := new([3]*bn256.G1)
	keyProd := new([3]*bn256.G1)
	for j := 0; j < 3; j++ {
		ctProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		keyProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		for i, e := range rowToAttrib {
			ctProd[j].Add(ctProd[j], new(bn256.G1).ScalarMult(ctForKey[i][j], alpha[i]))
			keyProd[j].Add(keyProd[j], new(bn256.G1).ScalarMult(key.k[key.attribToI[e]][j], alpha[i]))
		}
		keyProd[j].Add(keyProd[j], key.kPrime[j])
		ctPairing := bn256.Pair(ctProd[j], key.k0[j])
		keyPairing := bn256.Pair(keyProd[j], cipher.ct0[j])
		keyPairing.Neg(keyPairing)
		ret.Add(ret, ctPairing)
		ret.Add(ret, keyPairing)
	}

	return ret, nil
}
