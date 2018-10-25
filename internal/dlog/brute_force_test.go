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

package dlog

import (
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/assert"
)

func TestBruteForceBN256(t *testing.T) {
	xCheck := big.NewInt(1000)
	bound := big.NewInt(1000)
	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)
	h := new(bn256.GT).ScalarMult(g, xCheck)

	x, err := bruteForceBN256(h, g, bound)
	if err != nil {
		t.Fatalf("error in brute force algorithm: %v", err)
	}
	assert.Equal(t, xCheck.Cmp(x), 0, "obtained incorrect result")
}
