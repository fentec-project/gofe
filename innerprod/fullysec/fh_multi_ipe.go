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
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// L (int): The length of vectors to be encrypted.
// BoundX (int): The value by which coordinates of encrypted vectors x are bounded.
// BoundY (int): The value by which coordinates of inner product vectors y are bounded.
type FHIPEParams struct {
	L      int
	BoundX *big.Int
	BoundY *big.Int
}

// FHIPE represents a Function Hiding Inner Product Encryption scheme
// based on the paper by Kim, Lewi, Mandal, Montgomery, Roy, Wu:
// "Function-Hiding Inner Product Encryption is Practical".
// It allows to encrypt a vector x and derive a secret key based
// on an inner product vector y so that a deryptor can decrypt the
// inner product <x,y> without revealing x or y.
// The struct contains the shared choice for parameters on which
// the functionality of the scheme depend.
type FHMultiIPE struct {
	NumClients int
	VecLen     int
	SecLevel   int
}

type FHMultiIPEPubKey struct {
	GTMu *bn256.GT
}

type FHMultiIPESecKey struct {
	BHat     []data.MatrixG1
	BStarHat []data.MatrixG2
}

func NewFHMultiIPE(numClients, vecLen, secLevel int) *FHMultiIPE {
	return &FHMultiIPE{NumClients: numClients, VecLen: vecLen, SecLevel: secLevel}
}

func (f FHMultiIPE) GenerateKeys() (*FHMultiIPESecKey, *FHMultiIPEPubKey, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	gTMu := new(bn256.GT).ScalarBaseMult(mu)

	B := make([]data.MatrixG1, f.NumClients)
	BStar := make([]data.MatrixG2, f.NumClients)
	for i := 0; i < f.NumClients; i++ {
		B[i], BStar[i], err = randomOB(2*f.VecLen+2*f.SecLevel+1, mu)
		if err != nil {
			return nil, nil, err
		}
	}

	BHat := make([]data.MatrixG1, f.NumClients)
	BStarHat := make([]data.MatrixG2, f.NumClients)
	for i := 0; i < f.NumClients; i++ {
		BHat[i] = make(data.MatrixG1, f.VecLen+f.SecLevel)
		BStarHat[i] = make(data.MatrixG2, f.VecLen+f.SecLevel)
		for j := 0; j < f.VecLen+f.SecLevel; j++ {
			if j < f.VecLen {
				BHat[i][j] = B[i][j]
				BStarHat[i][j] = BStar[i][j]
			} else {
				BHat[i][j] = B[i][j+f.VecLen+f.SecLevel]
				BStarHat[i][j] = BStar[i][j+f.VecLen]
			}
		}
	}

	return &FHMultiIPESecKey{BHat: BHat, BStarHat: BStarHat},
		&FHMultiIPEPubKey{GTMu: gTMu}, nil
}

func randomOB(l int, mu *big.Int) (data.MatrixG1, data.MatrixG2, error) {
	sampler := sample.NewUniform(bn256.Order)
	BMat, err := data.NewRandomMatrix(l, l, sampler)
	if err != nil {
		return nil, nil, err
	}

	BStarMat, _, err := BMat.InverseModGauss(bn256.Order)
	if err != nil {
		return nil, nil, err
	}
	BStarMat = BStarMat.Transpose()
	BStarMat = BStarMat.MulScalar(mu)

	//B := make(data.MatrixG1, l)
	//zeroVec := data.NewConstantVector(l, big.NewInt(0))
	//for i:=0; i<l; i++ {
	//	Bi := zeroVec.MulG1()
	//	for j := 0; j < l; j++ {
	//		Ai := zeroVec
	//	}
	//}

	B := BMat.MulG1()
	BStar := BStarMat.MulG2()

	return B, BStar, nil
}
