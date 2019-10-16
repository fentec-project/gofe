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

func TestFH_Multi_IPE(t *testing.T) {
	// choose the parameters for the encryption and build the scheme
	secLevel := 2
	vecLen := 1
	numClient := 100
	bound := big.NewInt(10)


	fhmulti := fullysec.NewFHMultiIPE(numClient, vecLen, secLevel, bound, bound)

	// generate master key
	masterSecKey, pubKey, err := fhmulti.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during master key generation: %v", err)
	}

	// sample a vector that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)
	x := make(data.Matrix, numClient)
	for i := 0; i < numClient; i++ {
		x[i], err = data.NewRandomVector(vecLen, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
	}


	//// simulate the instantiation of an encryptor (which should know the master key)
	//encryptor := fullysec.NewFHIPEFromParams(fhipe.Params)
	//// encrypt the vector
	//ciphertext, err := encryptor.Encrypt(x, masterSecKey)
	//if err != nil {
	//	t.Fatalf("Error during encryption: %v", err)
	//}

	cipher := make(data.MatrixG1, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fhmulti.Encrypt(x[i], masterSecKey.BHat[i])
	}


	// sample a inner product vector
	y := make(data.Matrix, numClient)
	for i := 0; i < numClient; i++ {
		y[i], err = data.NewRandomVector(vecLen, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
	}

	// derive a functional key for vector y
	key, err := fhmulti.DeriveKey(y, masterSecKey)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// simulate a decryptor
	//decryptor := fullysec.NewFHIPEFromParams(fhipe.Params)
	// decryptor decrypts the inner-product without knowing
	// vectors x and y
	xy, err := fhmulti.Decrypt(cipher, key, pubKey)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	xyCheck, err := x.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}
