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
	"fmt"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"math/big"
	"testing"
	"time"

	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/stretchr/testify/assert"
)

func TestSimple_RingLWE(t *testing.T) {
	l := 30
	sec := 75
	bx := big.NewInt(2)
	by := big.NewInt(2)

	sampler := sample.NewUniformRange(new(big.Int).Neg(bx), bx)
	y, _ := data.NewRandomVector(l, sampler)

	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	ringLWE, err := simple.NewRingLWE(sec, l, bx, by)
	X, _ := data.NewRandomMatrix(l, ringLWE.Params.N, sampler)
	xy, _ := X.Transpose().MulVec(y)

	assert.NoError(t, err)
	fmt.Print(ringLWE)
	start := time.Now()
	SK, err := ringLWE.GenerateSecretKey()
	assert.NoError(t, err)
	elapsed := time.Since(start)
	fmt.Println("sec key", elapsed.Seconds())

	_, err = ringLWE.GeneratePublicKey(emptyMat)
	assert.Error(t, err)
	start = time.Now()

	PK, err := ringLWE.GeneratePublicKey(SK)
	assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Println("pub key", elapsed.Seconds())

	_, err = ringLWE.DeriveKey(emptyVec, SK)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)
	start = time.Now()

	skY, err := ringLWE.DeriveKey(y, SK)
	assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Println("der key", elapsed.Seconds())

	_, err = ringLWE.Encrypt(emptyMat, PK)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X, emptyMat)
	assert.Error(t, err)

	start = time.Now()

	cipher, err := ringLWE.Encrypt(X, PK)
	assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Println("enc", elapsed.Seconds())

	start = time.Now()

	xyDecrypted, err := ringLWE.Decrypt(cipher, skY, y)
	assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Println("dec", elapsed.Seconds())
	for i:=0; i < ringLWE.Params.N; i++ {
		assert.Equal(t, xy[i].Cmp(xyDecrypted[i]), 0, "obtained incorrect inner product")

	}
}
