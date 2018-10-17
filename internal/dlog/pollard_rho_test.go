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
	"math/rand"
	"testing"
	"time"

	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/stretchr/testify/assert"
	emmy "github.com/xlab-si/emmy/crypto/common"
)

func TestPollardRho(t *testing.T) {
	params, err := getParams()
	if err != nil {
		t.Fatalf("Error during parameters generation: %v", err)
	}

	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), params.order)

	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h := new(big.Int).Exp(params.g, xCheck, params.p)

	x, err := pollardRho(h, params.g, params.p, params.order)

	if err != nil {
		t.Fatalf("Error in Pollard rho algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x, "pollardRho result is wrong")
}

func TestPollardRhoParallel(t *testing.T) {
	params, err := getParams()
	if err != nil {
		t.Fatalf("Error during parameters generation: %v", err)
	}

	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), params.order)

	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h := new(big.Int).Exp(params.g, xCheck, params.p)
	x, err := pollardRhoParallel(h, params.g, params.p, params.order)

	if err != nil {
		t.Fatalf("Error in Pollard rho algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x, "pollardRho result is wrong")
}

func TestPollardRhoFactorization(t *testing.T) {
	n := emmy.GetRandomIntOfLength(32)
	factorization, err := pollardRhoFactorization(n, nil)

	if err != nil {
		t.Fatalf("error in pollard rho factorization: %v", err)
	}

	checkFactorization(factorization, n, t)
}

// Pollard rho with ElGamal group
func TestPollardRhoElGamal(t *testing.T) {
	modulusLength := 32

	key, err := keygen.NewElGamal(modulusLength)
	if err != nil {
		t.Fatalf("Error in group generation: %v", err)
	}

	order := key.Q
	xCheck, err := emmy.GetRandomIntFromRange(big.NewInt(2), order)

	if err != nil {
		t.Fatalf("Error during random int generation: %v", err)
	}

	h := new(big.Int).Exp(key.G, xCheck, key.P)
	x, err := pollardRho(h, key.G, key.P, order)

	if err != nil {
		t.Fatalf("Error in Pollard rho algorithm: %v", err)
	}

	assert.Equal(t, xCheck, x, "pollardRho result is wrong")
}

func checkFactorization(factorization map[string]int, n *big.Int, t *testing.T) {
	nCheck := big.NewInt(1)

	for prime, power := range factorization {
		prime := new(big.Int).SetBytes([]byte(prime))

		if !prime.ProbablyPrime(10) {
			t.Errorf("%d is not prime, but should be", prime)
		}

		nCheck.Mul(nCheck, new(big.Int).Exp(prime, big.NewInt(int64(power)), big.NewInt(0)))
	}

	assert.Equal(t, n, nCheck, "Product of factor powers should match original number")
}

// Hard factorization problem - the number is a product of two large primes
func TestPollardRhoFactorizationHard(t *testing.T) {
	p := emmy.GetGermainPrime(35)
	q := emmy.GetGermainPrime(35)

	n := new(big.Int).Mul(p, q)

	factorization, err := pollardRhoFactorization(n, nil)

	if err != nil {
		t.Fatalf("error in pollard rho factorization: %v", err)
	}

	checkFactorization(factorization, n, t)
}

// Run Pollard rho factorization on a smooth number.
func TestPollardRhoFactorizationBounded(t *testing.T) {
	B := smallPrimes[len(smallPrimes)-1]
	n := getSmoothNumber(B, 30, 10)
	factorization, err := pollardRhoFactorization(n, big.NewInt(int64(B)))

	if err != nil {
		t.Fatalf("error in bounded pollard rho factorization: %v", err)
	}

	checkFactorization(factorization, n, t)
}

func getSmoothNumber(B, numPrimes, maxPower int) *big.Int {

	// find the index of the maximal allowed factor
	indexBound := len(smallPrimes)
	for i, p := range smallPrimes {
		if p > B {
			indexBound = i
			break
		}
	}

	rand.Seed(time.Now().UTC().UnixNano())
	prod := big.NewInt(1)

	// pick a random prime < B and a random power < 10, numPrimes times
	// multiply the cumulative product by prime ^ power
	for i := 0; i < numPrimes; i++ {
		prime := smallPrimes[rand.Intn(indexBound)]
		power := rand.Intn(maxPower + 1)
		prod.Mul(prod, new(big.Int).Exp(big.NewInt(int64(prime)), big.NewInt(int64(power)), big.NewInt(0)))
	}

	return prod
}
