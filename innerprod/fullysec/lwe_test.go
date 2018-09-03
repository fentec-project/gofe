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
	P := big.NewInt(4) // maximal size of the entry of the message
	V := big.NewInt(4) // maximal size of the entry of the other operand for inner product
	//q, _ := new(big.Int).SetString("80000273017373644747761631204419146913522365603493191", 10)

	x, y, xy := testVectorData(l, P, V)
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	//eps := math.Pow(2, 32)
	//k := float64(256)
	//sigma := new(big.Float).SetFloat64(1.1791095524314183e-19)

	fsLWE, err := fullysec.NewLWE(l, n, P, V)
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
	_, err = fsLWE.DeriveKey(y.MulScalar(big.NewInt(2)), emptyMat)
	assert.Error(t, err) // boundary violation
	zX, err := fsLWE.DeriveKey(y, Z)
	assert.NoError(t, err)

	_, err = fsLWE.Encrypt(emptyVec, U)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x, emptyMat)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x.MulScalar(big.NewInt(2)), U)
	assert.Error(t, err) // boundary violation
	cipher, err := fsLWE.Encrypt(x, U)
	assert.NoError(t, err)

	_, err = fsLWE.Decrypt(emptyVec, zX, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, emptyVec, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zX, emptyVec)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zX, y.MulScalar(big.NewInt(2)))
	assert.Error(t, err) // boundary violation
	xyDecrypted, err := fsLWE.Decrypt(cipher, zX, y)
	assert.NoError(t, err)
	assert.Equal(t, xy, xyDecrypted, "obtained incorrect inner product")
}

// testVectorData returns random vectors x, y, each containing
// elements up to the respective bound.
// It also returns the dot product of the vectors.
func testVectorData(len int, xBound, yBound *big.Int) (data.Vector, data.Vector, *big.Int) {
	x, _ := data.NewRandomVector(len, sample.NewUniform(xBound))
	y, _ := data.NewRandomVector(len, sample.NewUniform(yBound))
	xy, _ := x.Dot(y)

	return x, y, xy
}
