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

package abe_test

import (
	"testing"

	"github.com/fentec-project/gofe/abe"
)

func TestDIPPE(t *testing.T) {
	// create a new FAME struct with the universe of attributes
	// denoted by integer
	d, err := abe.NewDIPPE(2)
	if err != nil {
		t.Fatalf("Failed to generate a new scheme: %v", err)
	}

	// generate a public key and a secret key for the scheme
	auth := make([]*abe.DIPPEAuth, 2)
	for i := 0; i < 2; i++ {
		auth[i], err = d.NewDIPPEAuth()
		if err != nil {
			t.Fatalf("Failed to generate a new authority: %v", err)
		}
	}


}