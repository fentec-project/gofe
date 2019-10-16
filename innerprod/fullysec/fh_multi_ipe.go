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
	"github.com/fentec-project/gofe/internal/dlog"
	"time"
	"fmt"
)

// L (int): The length of vectors to be encrypted.
// BoundX (int): The value by which coordinates of encrypted vectors x are bounded.
// BoundY (int): The value by which coordinates of inner product vectors y are bounded.
type FHMultiIPEParams struct {
	NumClients int
	VecLen     int
	SecLevel   int
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
	Params *FHMultiIPEParams
}

type FHMultiIPESecKey struct {
	BHat     []data.MatrixG1
	BStarHat []data.MatrixG2
}

func NewFHMultiIPE(numClients, vecLen, secLevel int, boundX, boundY *big.Int) *FHMultiIPE {
	params := &FHMultiIPEParams{NumClients: numClients, VecLen: vecLen,
		SecLevel: secLevel, BoundX: boundX, BoundY:boundY}
	return &FHMultiIPE{Params: params}
}

func (f FHMultiIPE) GenerateKeys() (*FHMultiIPESecKey, *bn256.GT, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}
	gTMu := new(bn256.GT).ScalarBaseMult(mu)

	B := make([]data.MatrixG1, f.Params.NumClients)
	BStar := make([]data.MatrixG2, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		start := time.Now()

		B[i], BStar[i], err = randomOB(2*f.Params.VecLen+2*f.Params.SecLevel+1, mu)
		t := time.Now()
		elapsed := t.Sub(start)
		fmt.Println(elapsed)
		if err != nil {
			return nil, nil, err
		}
	}

	BHat := make([]data.MatrixG1, f.Params.NumClients)
	BStarHat := make([]data.MatrixG2, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		BHat[i] = make(data.MatrixG1, f.Params.VecLen+f.Params.SecLevel+1)
		BStarHat[i] = make(data.MatrixG2, f.Params.VecLen+f.Params.SecLevel)
		for j := 0; j < f.Params.VecLen+f.Params.SecLevel+1; j++ {
			if j < f.Params.VecLen {
				BHat[i][j] = B[i][j]
				BStarHat[i][j] = BStar[i][j]
			} else if j == f.Params.VecLen {
				BHat[i][j] = B[i][j+f.Params.VecLen]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else if j < f.Params.VecLen+f.Params.SecLevel{
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else {
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
			}
		}
	}

	return &FHMultiIPESecKey{BHat: BHat, BStarHat: BStarHat}, gTMu, nil
}

func randomOB(l int, mu *big.Int) (data.MatrixG1, data.MatrixG2, error) {
	sampler := sample.NewUniform(bn256.Order)
	BMat, err := data.NewRandomMatrix(l, l, sampler)
	if err != nil {
		return nil, nil, err
	}


	start := time.Now()

	BStarMat, _, err := BMat.InverseModGauss(bn256.Order)




	if err != nil {
		return nil, nil, err
	}
	BStarMat = BStarMat.Transpose()
	BStarMat = BStarMat.MulScalar(mu)
	BStarMat = BStarMat.Mod(bn256.Order)



	B := BMat.MulG1()

	t := time.Now()
	elapsed := t.Sub(start)
	fmt.Println(elapsed)
	BStar := BStarMat.MulG2()


	return B, BStar, nil
}

func (f FHMultiIPE) DeriveKey(y data.Matrix, secKey *FHMultiIPESecKey) (data.MatrixG2, error) {
	sampler := sample.NewUniform(bn256.Order)
	gamma, err := data.NewRandomMatrix(f.Params.SecLevel, f.Params.NumClients, sampler)
	if err != nil {
		return nil, err
	}

	ones := data.NewConstantVector(f.Params.NumClients-1, big.NewInt(1))
	r := data.NewVector(gamma[0][0:(f.Params.NumClients - 1)])
	sum, err := r.Dot(ones)
	if err != nil {
		return nil, err
	}

	sum.Neg(sum).Mod(sum, bn256.Order)
	gamma[0][f.Params.NumClients-1] = sum

	zeros := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	key := make(data.MatrixG2, f.Params.NumClients)
	var s *big.Int
	for i := 0; i < f.Params.NumClients; i++ {
		key[i] = zeros.MulG2()
		for j := 0; j < f.Params.VecLen + f.Params.SecLevel; j++ {
			if j < f.Params.VecLen {
				s = y[i][j]

			} else {
				s = gamma[j - f.Params.VecLen][i]
			}

			key[i] = key[i].Add(secKey.BStarHat[i][j].MulScalar(s))
		}
	}

	return key, nil
}

func (f FHMultiIPE) Encrypt(x data.Vector, partSecKey data.MatrixG1) (data.VectorG1, error) {
	sampler := sample.NewUniform(bn256.Order)
	phi, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	zeros := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	key := zeros.MulG1()
	var s *big.Int
	for j := 0; j < f.Params.VecLen + f.Params.SecLevel + 1; j++ {
		if j < f.Params.VecLen {
			s = x[j]

		} else if j == f.Params.VecLen {
			s = big.NewInt(1)
		} else {
			s = phi[j - f.Params.VecLen - 1]
		}

		key = key.Add(partSecKey[j].MulScalar(s))
	}

	return key, nil
}

// Decrypt accepts the ciphertext and functional encryption key.
// It returns the inner product of x and y. If decryption failed,
// an error is returned.
func (f *FHMultiIPE) Decrypt(cipher data.MatrixG1, key data.MatrixG2, pubKey *bn256.GT) (*big.Int, error) {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < 2 * f.Params.VecLen + 2 *f.Params.SecLevel + 1; j++ {
			paired := bn256.Pair(cipher[i][j], key[i][j])
			sum.Add(paired, sum)
		}
	}

	boundXY := new(big.Int).Mul(f.Params.BoundX, f.Params.BoundY)
	bound := new(big.Int).Mul(big.NewInt(int64(f.Params.NumClients * f.Params.VecLen)), boundXY)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(sum, pubKey)

	return dec, err
}
