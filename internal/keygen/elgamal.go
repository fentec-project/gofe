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

	emmy "github.com/xlab-si/emmy/crypto/common"
)

type ElGamal struct {
	Y *big.Int // public key
	G *big.Int // generator
	P *big.Int // modulus
	Q *big.Int // order
}

// adapted from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py
func NewElGamal(modulusLength int) (*ElGamal, error) {
	p, err := emmy.GetSafePrime(modulusLength)
	g := big.NewInt(0)

	if err != nil {
		return nil, fmt.Errorf("failed to generate safe prime")
	}

	for {
		r, err := emmy.GetRandomIntFromRange(big.NewInt(2), p)
		if err != nil {
			return nil, err
		}

		g = new(big.Int).Exp(r, big.NewInt(2), p)

		if g.Cmp(big.NewInt(2)) < 1 {
			continue
		}

		if new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), g).Cmp(big.NewInt(0)) == 0 {
			continue
		}

		gInv := new(big.Int).ModInverse(g, p)
		if new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), gInv).Cmp(big.NewInt(0)) == 0 {
			continue
		}

		break
	}

	x, err := emmy.GetRandomIntFromRange(big.NewInt(2), new(big.Int).Sub(p, big.NewInt(1)))
	if err != nil {
		return nil, err
	}

	y := new(big.Int).Exp(g, x, p)

	// order: q = (p - 1) / 2
	q := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2))

	return &ElGamal{
		Y: y,
		G: g,
		P: p,
		Q: q,
	}, nil
}
