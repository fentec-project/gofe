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
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestSimple_RingLWE(t *testing.T) {
	l := 100
	n := 256
	b := big.NewInt(1000000)
	p, _ := new(big.Int).SetString("10000000000000000", 10)
	q, _ := new(big.Int).SetString("903468688179973616387830299599", 10)

	sigma := big.NewFloat(20)

	sampler := sample.NewUniformRange(new(big.Int).Neg(b), b)
	y, _ := data.NewRandomVector(l, sampler)
	X, _ := data.NewRandomMatrix(l, n, sampler)
	xy, _ := X.Transpose().MulVec(y)
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	_, err := simple.NewRingLWE(l, 24, b, p, q, sigma)
	assert.Error(t, err) // n not a power of 2
	_, err = simple.NewRingLWE(l, n, b, big.NewInt(10), q, sigma)
	assert.Error(t, err) // precondition failed
	ringLWE, err := simple.NewRingLWE(l, n, b, p, q, sigma)
	assert.NoError(t, err)

	SK, err := ringLWE.GenerateSecretKey()
	assert.NoError(t, err)

	_, err = ringLWE.GeneratePublicKey(emptyMat)
	assert.Error(t, err)
	PK, err := ringLWE.GeneratePublicKey(SK)
	assert.NoError(t, err)

	_, err = ringLWE.DeriveKey(emptyVec, SK)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y.MulScalar(b), SK)
	assert.Error(t, err) // boundary violated
	skY, err := ringLWE.DeriveKey(y, SK)
	assert.NoError(t, err)

	_, err = ringLWE.Encrypt(emptyMat, PK)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X, emptyMat)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X.MulScalar(b), PK)
	assert.Error(t, err) // boundary violated
	cipher, err := ringLWE.Encrypt(X, PK)
	assert.NoError(t, err)

	xyDecrypted, err := ringLWE.Decrypt(cipher, skY, y)
	assert.NoError(t, err)
	assert.Equal(t, xy, xyDecrypted, "obtained incorrect inner product")
}
