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

package fullysec

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/internal/keygen"
	"github.com/fentec-project/gofe/sample"
)

// PaillierParams represents parameters for the fully secure Paillier scheme.
type PaillierParams struct {
	L       int        // Length of data vectors for inner product
	N       *big.Int   // a big integer, a product of two safe primes
	NSquare *big.Int   // N^2 a modulus for computations
	BoundX  *big.Int   // a bound on the entries of the input vector
	BoundY  *big.Int   // a bound on the entries of the inner product vector
	Sigma   *big.Float // the standard deviation for the sampling a secret key
	LSigma  *big.Int   // precomputed Sigma/(1/2log(2)) needed for sampling
	Lambda  int        // security parameter
	G       *big.Int   // generator of the 2n-th residues subgroup of Z_N^2*
}

// Paillier represents a scheme based on the Paillier variant by
// Agrawal, Shweta, Libert, and Stehle":
// "Fully secure functional encryption for inner products,
// from standard assumptions".
type Paillier struct {
	Params *PaillierParams
}

// NewPaillier configures a new instance of the scheme.
// It accepts the length of input vectors l, security parameter lambda,
// the bit length of prime numbers (giving security to the scheme, it
// should be such that factoring two primes with such a bit length takes
// at least 2^lambda operations), and boundX and boundY by which
// coordinates of input vectors and inner product vectors are bounded.
//
// It returns an error in the case the scheme could not be properly
// configured, or if the precondition boundX, boundY < (n / l)^(1/2)
// is not satisfied.
func NewPaillier(l, lambda, bitLen int, boundX, boundY *big.Int) (*Paillier, error) {
	// generate two safe primes
	p, err := keygen.GetSafePrime(bitLen)
	if err != nil {
		return nil, err
	}

	q, err := keygen.GetSafePrime(bitLen)
	if err != nil {
		return nil, err
	}

	// calculate n = p * q
	n := new(big.Int).Mul(p, q)

	// calculate n^2
	nSquare := new(big.Int).Mul(n, n)

	// check if the parameters of the scheme are compatible,
	// i.e. security parameter should be big enough that
	// the generated n is much greater than l and the bounds
	xSquareL := new(big.Int).Mul(boundX, boundX)
	xSquareL.Mul(xSquareL, big.NewInt(int64(2*l)))
	ySquareL := new(big.Int).Mul(boundY, boundY)
	ySquareL.Mul(ySquareL, big.NewInt(int64(2*l)))
	if n.Cmp(xSquareL) < 1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundX and l too big for bitLen")
	}
	if n.Cmp(ySquareL) < 1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundY and l too big for bitLen")
	}

	// generate a generator for the 2n-th residues subgroup of Z_n^2*
	gPrime, err := rand.Int(rand.Reader, nSquare)
	if err != nil {
		return nil, err
	}
	g := new(big.Int).Exp(gPrime, n, nSquare)
	g.Exp(g, big.NewInt(2), nSquare)

	// check if generated g is invertible, which should be the case except with
	// negligible probability
	if check := new(big.Int).ModInverse(g, nSquare); check == nil {
		return nil, fmt.Errorf("parameters generation failed," +
			"unexpected event of generator g is not invertible")
	}

	// calculate sigma
	nTo5 := new(big.Int).Exp(n, big.NewInt(5), nil)
	sigma := new(big.Float).SetInt(nTo5)
	sigma.Mul(sigma, big.NewFloat(float64(lambda)))
	sigma.Sqrt(sigma)
	sigma.Add(sigma, big.NewFloat(2))
	// to sample with NormalDoubleConstant sigma must be
	// a multiple of sample.SigmaCDT = 1/(2ln(2)), hence we make
	// it such
	lSigmaF := new(big.Float).Quo(sigma, sample.SigmaCDT)
	lSigma, _ := lSigmaF.Int(nil)
	lSigma.Add(lSigma, big.NewInt(1))
	sigma.Mul(sample.SigmaCDT, lSigmaF)

	return &Paillier{
		Params: &PaillierParams{
			L:       l,
			N:       n,
			NSquare: nSquare,
			BoundX:  boundX,
			BoundY:  boundY,
			Sigma:   sigma,
			LSigma:  lSigma,
			Lambda:  lambda,
			G:       g,
		},
	}, nil
}

// NewPaillierFromParams takes configuration parameters of an existing
// Paillier scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new Paillier instance.
func NewPaillierFromParams(params *PaillierParams) *Paillier {
	return &Paillier{
		Params: params,
	}
}

// GenerateMasterKeys generates a master secret key and a master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (s *Paillier) GenerateMasterKeys() (data.Vector, data.Vector, error) {
	// sampler for sampling a secret key
	sampler := sample.NewNormalDoubleConstant(s.Params.LSigma)

	// generate a secret key
	secKey, err := data.NewRandomVector(s.Params.L, sampler)
	if err != nil {
		return nil, nil, err
	}

	// derive the public key from the generated secret key
	pubKey := secKey.Apply(func(x *big.Int) *big.Int {
		return internal.ModExp(s.Params.G, x, s.Params.NSquare)
	})
	return secKey, pubKey, nil
}

// DeriveKey accepts master secret key masterSecKey and input vector y, and derives a
// functional encryption key for the inner product with y.
// In case of malformed secret key or input vector that violates the configured
// bound, it returns an error.
func (s *Paillier) DeriveKey(masterSecKey data.Vector, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}

	return masterSecKey.Dot(y)
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (s *Paillier) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(s.Params.BoundX); err != nil {
		return nil, err
	}

	// generate a randomness for the encryption
	nOver4 := new(big.Int).Quo(s.Params.N, big.NewInt(4))
	r, err := rand.Int(rand.Reader, nOver4)
	if err != nil {
		return nil, err
	}

	// encrypt x under randomness r
	cipher := make(data.Vector, s.Params.L+1)
	// c_0 = g^r in Z_n^2
	c0 := new(big.Int).Exp(s.Params.G, r, s.Params.NSquare)
	cipher[0] = c0
	for i := 0; i < s.Params.L; i++ {
		// c_i = (1 + x_i * n) * pubKey_i^r in Z_n^2
		t1 := new(big.Int).Mul(x[i], s.Params.N)
		t1.Add(t1, big.NewInt(1))
		t2 := new(big.Int).Exp(masterPubKey[i], r, s.Params.NSquare)
		ct := new(big.Int).Mul(t1, t2)
		ct.Mod(ct, s.Params.NSquare)
		cipher[i+1] = ct
	}

	return cipher, nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a vector y. It returns the inner product of x and y.
func (s *Paillier) Decrypt(cipher data.Vector, key *big.Int, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	// tmp value cX is calculated as (prod_{i=1 to l} c_i^y_i) * c_0^(-key) in Z_n^2
	keyNeg := new(big.Int).Neg(key)
	cX := internal.ModExp(cipher[0], keyNeg, s.Params.NSquare)

	for i, ct := range cipher[1:] {
		t1 := internal.ModExp(ct, y[i], s.Params.NSquare)
		cX.Mul(cX, t1)
		cX.Mod(cX, s.Params.NSquare)
	}

	// decryption is calculated as (cX-1 mod n^2)/n
	cX.Sub(cX, big.NewInt(1))
	cX.Mod(cX, s.Params.NSquare)
	ret := new(big.Int).Quo(cX, s.Params.N)
	// if the return value is negative this is seen as the above ret being
	// greater than n/2; in this case ret = ret - n
	nHalf := new(big.Int).Quo(s.Params.N, big.NewInt(2))
	if ret.Cmp(nHalf) == 1 {
		ret.Sub(ret, s.Params.N)
	}

	return ret, nil
}
