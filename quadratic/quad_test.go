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

package quadratic_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/quadratic"
	"fmt"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestQuad(t *testing.T) {
	bound := big.NewInt(100)
	sampler := sample.NewUniform(bound)
	n := 100
	f, err := data.NewRandomMatrix(n, n, sampler)
	if err != nil {
		t.Fatalf("error when generating random matrix: %v", err)
	}

	q := quadratic.NewQuad(n, n, bound)
	pubKey, secKey, err := q.GenerateKeys()
	if err != nil {
		t.Fatalf("error when generating keys: %v", err)
	}


	x, err := data.NewRandomVector(n, sampler)
	if err != nil {
		t.Fatalf("error when generating random vector: %v", err)
	}
	y, err := data.NewRandomVector(n, sampler)
	if err != nil {
		t.Fatalf("error when generating random vector: %v", err)
	}


	c, err := q.Encrypt(x, y, pubKey)
	if err != nil {
		t.Fatalf("error when encrypting: %v", err)
	}

	feKey, err := q.DeriveKey(secKey, f)
	if err != nil {
		t.Fatalf("error when deriving key: %v", err)
	}

	fmt.Println(c, feKey)

	check, err := f.MulXMatY(x, y)
	if err != nil {
		t.Fatalf("error when computing x*F*y: %v", err)
	}

	fmt.Println(check)
	dec, err := q.Decrypt(c, feKey, f)
	if err != nil {
		t.Fatalf("error when decrypting: %v", err)
	}

	assert.Equal(t, check, dec, "Decryption wrong")
}
