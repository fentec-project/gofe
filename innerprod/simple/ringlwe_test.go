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

package simple_test

import (
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/stretchr/testify/assert"
)

func TestSimple_RingLWE(t *testing.T) {
	// choose meta-parameters
	l := 30 // l-dimensional vectors
	sec := 75 // min bits of security
	bx := big.NewInt(2) // bound for the input coordinates
	by := big.NewInt(2) // bound for the inner-product coordinates

	// setup a ringLWE scheme
	ringLWE, err := simple.NewRingLWE(sec, l, bx, by)
	assert.NoError(t, err)

	// sample an input and an inner-product vector
	sampler := sample.NewUniformRange(new(big.Int).Neg(bx), bx)
	y, _ := data.NewRandomVector(l, sampler)
	dimX := ringLWE.Params.N / 2
	X, _ := data.NewRandomMatrix(l, dimX, sampler)
	xy, _ := X.Transpose().MulVec(y)

	// generate a master secret key
	SK, err := ringLWE.GenerateSecretKey()
	assert.NoError(t, err)

    // generate a public key
	PK, err := ringLWE.GeneratePublicKey(SK)
	assert.NoError(t, err)

	// check if errors are raised if the input is of the wrong form
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}
	_, err = ringLWE.GeneratePublicKey(emptyMat)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(emptyVec, SK)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)

	// derive FE key with respect to y
	skY, err := ringLWE.DeriveKey(y, SK)
	assert.NoError(t, err)

	// encrypt a matrix X
	cipher, err := ringLWE.Encrypt(X, PK)
	assert.NoError(t, err)

	// check if errors are raised if the input is of the wrong form
	_, err = ringLWE.Encrypt(emptyMat, PK)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X, emptyMat)
	assert.Error(t, err)

	// decrypt the product y^T * X using the derived key
	xyDecrypted, err := ringLWE.Decrypt(cipher, skY, y)
	assert.NoError(t, err)
	// check the result
	for i:=0; i < dimX; i++ {
		assert.Equal(t, xy[i].Cmp(xyDecrypted[i]), 0, "obtained incorrect inner product")
	}
}
