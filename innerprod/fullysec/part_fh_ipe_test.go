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
	"fmt"
	"github.com/stretchr/testify/assert"
)

func TestPartFHIPE(t *testing.T) {
	// choose the parameters for the encryption and build the scheme
	l := 50
	k := 5
	bound := big.NewInt(2)
	sampler := sample.NewUniform(bound)
	//sampler = sample.NewUniformRange(big.NewInt(1), big.NewInt(2))


	m, err := data.NewRandomMatrix(l, k, sampler)
	if err != nil {
		t.Fatalf("Error during random matrix generation: %v", err)
	}
	//m[0][0] = big.NewInt(1)
	//det, err := m.Determinant()
	//if err != nil || det.Sign() == 0 {
	//	t.Fatalf("Error during random matrix generation: %v", err)
	//}




	partfhipe:= fullysec.NewPartFHIPE(l, k, bound)

	// generate master key
	pubKey, secKey, err := partfhipe.GenerateKeys(m)
	if err != nil {
		t.Fatalf("Error during master key generation: %v", err)
	}

	fmt.Println("pub", pubKey)
	fmt.Println("sec", secKey)

	// sample a vector that will be encrypted
	x, err := data.NewRandomVector(k, sampler)
	if err != nil {
		t.Fatalf("Error during random vector generation: %v", err)
	}

	// simulate the instantiation of an encryptor (which should know the master key)
	encryptor := fullysec.NewPartFHIPEFromParams(partfhipe.Params)
	// encrypt the vector
	ciphertext, err := encryptor.Encrypt(x, pubKey)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	// sample a inner product vector
	y, err := data.NewRandomVector(l, sampler)
	if err != nil {
		t.Fatalf("Error during random vecotr generation: %v", err)
	}

	// derive a functional key for vector y
	feKey, err := partfhipe.DeriveKey(y, secKey)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	//fmt.Println(feKey, pubKey)
	Mx, err := m.MulVec(x)
	yMyCheck, err := y.Dot(Mx)

	fmt.Println(y, m, x, yMyCheck)


	// simulate a decryptor
	decryptor := fullysec.NewPartFHIPEFromParams(partfhipe.Params)
	// decryptor decrypts the inner-product without knowing
	// vectors x and y
	xMy, err := decryptor.Decrypt(ciphertext, feKey)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}
	fmt.Println(xMy, yMyCheck)

	// check the correctness of the result

	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}




	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xMy.Cmp(yMyCheck), 0, "obtained incorrect inner product")
}
