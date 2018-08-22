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
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

// Simply brute-forces all possible options.
func bruteForce(h, g, p, bound *big.Int) (*big.Int, error) {
	if bound == nil {
		bound = new(big.Int).Sub(p, big.NewInt(1))
	}

	for i := big.NewInt(0); i.Cmp(bound) < 0; i.Add(i, big.NewInt(1)) {
		if new(big.Int).Exp(g, i, p).Cmp(h) == 0 {
			return i, nil
		}
	}

	return nil, fmt.Errorf("failed to find discrete logarithm within bound")
}

// Simply brute-forces all possible options to compute dlog in BN256 GT group.
func bruteForceBN256(h, g *bn256.GT, bound *big.Int) (*big.Int, error) {
	if bound == nil {
		bound = bn256.Order
	}

	for i := big.NewInt(0); i.Cmp(bound) <= 0; i.Add(i, big.NewInt(1)) {
		t := new(bn256.GT).ScalarMult(g, i)
		if t.String() == h.String() {
			return i, nil
		}
	}

	return nil, fmt.Errorf("failed to find discrete logarithm within bound")
}
