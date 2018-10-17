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

package fullysec_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestFullySec_LWE(t *testing.T) {
	l := 4
	n := 64
	boundX := big.NewInt(1000) // maximal size of the entry of the message
	boundY := big.NewInt(1000) // maximal size of the entry of the other operand for inner product

	x, y, xy := testVectorData(l, boundX, boundY)
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	fsLWE, err := fullysec.NewLWE(l, n, boundX, boundY)
	assert.NoError(t, err)

	Z, err := fsLWE.GenerateSecretKey()
	assert.NoError(t, err)

	_, err = fsLWE.GeneratePublicKey(emptyMat)
	assert.Error(t, err)
	U, err := fsLWE.GeneratePublicKey(Z)
	assert.NoError(t, err)

	_, err = fsLWE.DeriveKey(emptyVec, Z)
	assert.Error(t, err)
	_, err = fsLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)
	_, err = fsLWE.DeriveKey(y.MulScalar(big.NewInt(1000)), emptyMat)
	assert.Error(t, err) // boundary violation
	zY, err := fsLWE.DeriveKey(y, Z)
	assert.NoError(t, err)

	_, err = fsLWE.Encrypt(emptyVec, U)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x, emptyMat)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x.MulScalar(big.NewInt(1000)), U)
	assert.Error(t, err) // boundary violation
	cipher, err := fsLWE.Encrypt(x, U)
	assert.NoError(t, err)

	_, err = fsLWE.Decrypt(emptyVec, zY, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, emptyVec, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zY, emptyVec)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zY, y.MulScalar(big.NewInt(1000)))
	assert.Error(t, err) // boundary violation
	xyDecrypted, err := fsLWE.Decrypt(cipher, zY, y)
	assert.NoError(t, err)
	assert.Equal(t, xy.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
}

// testVectorData returns random vectors x, y, each containing
// elements up to the respective bound.
// It also returns the dot product of the vectors.
func testVectorData(len int, boundX, boundY *big.Int) (data.Vector, data.Vector, *big.Int) {
	samplerX := sample.NewUniformRange(new(big.Int).Neg(boundX), boundX)
	samplerY := sample.NewUniformRange(new(big.Int).Neg(boundY), boundY)
	x, _ := data.NewRandomVector(len, samplerX)
	y, _ := data.NewRandomVector(len, samplerY)
	xy, _ := x.Dot(y)

	return x, y, xy
}
