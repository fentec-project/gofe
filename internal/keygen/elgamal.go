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

package keygen

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/sample"
)

// ElGamal holds paramenters for ElGamal scheme.
type ElGamal struct {
	Y *big.Int // public key
	G *big.Int // generator
	P *big.Int // modulus
	Q *big.Int // (P - 1) / 2, i.e. order of G
}

// NewElGamal creates parameters for ElGamal scheme. Implementation is
// adapted from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py.
func NewElGamal(modulusLength int) (*ElGamal, error) {
	p, err := GetSafePrime(modulusLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate safe prime")
	}

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)

	// q = (p - 1) / 2
	q := new(big.Int).Sub(p, one)
	q.Div(q, two)
	g := new(big.Int)
	sampler := sample.NewUniformRange(three, p)

	for {
		g, err = sampler.Sample()
		if err != nil {
			return nil, err
		}

		// make g an element of the subgroup of quadratic residues
		g.Exp(g, two, p)

		// additional checks to avoid some known attacks
		if new(big.Int).Mod(new(big.Int).Sub(p, one), g).Cmp(zero) == 0 {
			continue
		}
		gInv := new(big.Int).ModInverse(g, p)
		if new(big.Int).Mod(new(big.Int).Sub(p, one), gInv).Cmp(zero) == 0 {
			continue
		}

		break
	}

	x, err := sampler.Sample()
	if err != nil {
		return nil, err
	}
	y := new(big.Int).Exp(g, x, p)

	return &ElGamal{
		Y: y,
		G: g,
		P: p,
		Q: q,
	}, nil
}
