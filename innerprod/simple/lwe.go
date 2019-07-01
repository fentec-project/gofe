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

package simple

import (
	"math/big"

	"crypto/rand"
	"math"
	"math/bits"

	"fmt"

	"github.com/fentec-project/gofe/data"
	gofe "github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"
)

// LWEParams represents parameters for the simple LWE scheme.
type LWEParams struct {
	L int // Length of data vectors for inner product

	N int // Main security parameters of the scheme
	M int // Number of rows (samples) for the LWE problem

	BoundX *big.Int // Bound for input vector coordinates (for x)
	BoundY *big.Int // Bound for inner product vector coordinates (for y)

	P *big.Int // Modulus for message space
	Q *big.Int // Modulus for ciphertext and keys

	SigmaQ *big.Float

	// Matrix A of dimensions M*N is a public parameter of the scheme
	A data.Matrix
}

// LWE represents a scheme instantiated from the LWE assumption,
// based on the LWE variant by
// Abdalla, Bourse, De Caro, and Pointchev:
// "Simple Functional Encryption Schemes for Inner Products".
type LWE struct {
	Params *LWEParams
}

// NewLWE configures a new instance of the scheme.
// It accepts the length of input vectors l, bound for coordinates of
// input vectors x and y, the main security parameters n and m,
// modulus for input data p, and modulus for ciphertext and keys q.
// Security parameters are generated so that they satisfy theoretical
// bounds provided in the phd thesis Functional Encryption for
// Inner-Product Evaluations, see Section 8.3.1 in
// https://www.di.ens.fr/~fbourse/publications/Thesis.pdf
// Note that this is a prototype implementation and should not be
// used in production before security testing against various
// known attacks has been performed. Unfortunately, no such (theoretical)
// evaluation exists yet in the literature.
//
// It returns an error in case public parameters of the scheme could
// not be generated.
func NewLWE(l int, boundX, boundY *big.Int, n int) (*LWE, error) {
	// generate parameters
	// p > boundX * boundY * l * 2
	nBitsP := boundX.BitLen() + boundY.BitLen() + bits.Len(uint(l)) + 2
	p, err := rand.Prime(rand.Reader, nBitsP)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate public parameters")
	}

	pF := new(big.Float).SetInt(p)
	boundXF := new(big.Float).SetInt(boundX)
	boundYF := new(big.Float).SetInt(boundY)

	val := new(big.Float).Mul(boundXF, big.NewFloat(math.Sqrt(float64(l))))
	val.Add(val, big.NewFloat(1))
	x := new(big.Float).Mul(val, pF)
	x.Mul(x, boundYF)
	x.Mul(x, big.NewFloat(float64(8*n)*math.Sqrt(float64(n+l+1))))
	xSqrt := new(big.Float).Sqrt(x)
	x.Mul(x, xSqrt)
	xI, _ := x.Int(nil)
	nBitsQ := xI.BitLen() + 1
	q, err := rand.Prime(rand.Reader, nBitsQ)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate public parameters")
	}

	m := (n+l+1)*nBitsQ + 2*n + 1

	sigma := new(big.Float)
	sigma.SetPrec(uint(n))
	sigma.Quo(big.NewFloat(1/(2*math.Sqrt(float64(2*l*m*n)))), pF)
	sigma.Quo(sigma, boundYF)
	qF := new(big.Float).SetInt(q)
	sigmaQ := new(big.Float).Mul(sigma, qF)
	// make it an integer for faster sampling using NormalDouble
	sigmaQI, _ := sigmaQ.Int(nil)
	sigmaQ.SetInt(sigmaQI)
	sigmaQ.Add(sigmaQ, big.NewFloat(1))

	// sanity check if the parameters satisfy theoretical bounds
	val.Quo(sigmaQ, val)
	if val.Cmp(big.NewFloat(2*math.Sqrt(float64(n)))) < 1 {
		return nil, fmt.Errorf("parameters generation faliled, sigmaQ too small")
	}

	// generate a random matrix
	A, err := data.NewRandomMatrix(m, n, sample.NewUniform(q))
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate public parameters")
	}
	return &LWE{
		Params: &LWEParams{
			L:      l,
			BoundX: boundX,
			BoundY: boundY,
			N:      n,
			M:      m,
			P:      p,
			Q:      q,
			A:      A,
			SigmaQ: sigmaQ,
		},
	}, nil
}

// GenerateSecretKey generates a secret key for the scheme.
// The key is represented by a matrix with dimensions n*l whose
// elements are random values from the interval [0, q).
//
// In case secret key could not be generated, it returns an error.
func (s *LWE) GenerateSecretKey() (data.Matrix, error) {
	return data.NewRandomMatrix(s.Params.N, s.Params.L, sample.NewUniform(s.Params.Q))
}

// GeneratePublicKey accepts a secret key SK, standard deviation sigma.
// It generates a public key PK for the scheme. Public key is a matrix
// of m*l elements.
//
// In case of a malformed secret key the function returns an error.
func (s *LWE) GeneratePublicKey(SK data.Matrix) (data.Matrix, error) {
	if !SK.CheckDims(s.Params.N, s.Params.L) {
		return nil, gofe.MalformedSecKey
	}

	// Initialize and fill noise matrix E with m*l samples
	sampler, err := sample.NewNormalDouble(s.Params.SigmaQ, uint(s.Params.N), big.NewFloat(1))
	if err != nil {
		return nil, errors.Wrap(err, "error generating public key")
	}

	E, err := data.NewRandomMatrix(s.Params.M, s.Params.L, sampler)
	if err != nil {
		return nil, errors.Wrap(err, "error generating public key")
	}

	// Calculate public key as PK = (A * SK + E) % q
	// we ignore error checks because they errors could only arise if SK
	// was not of the proper form, but we validated it at the beginning
	PK, _ := s.Params.A.Mul(SK)
	PK = PK.Mod(s.Params.Q)
	PK, _ = PK.Add(E)
	PK = PK.Mod(s.Params.Q)

	return PK, nil
}

// DeriveKey accepts input vector y and master secret key SK, and derives a
// functional encryption key.
//
// In case of malformed secret key or input vector that violates the configured
// bound, it returns an error.
func (s *LWE) DeriveKey(y data.Vector, SK data.Matrix) (data.Vector, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if !SK.CheckDims(s.Params.N, s.Params.L) {
		return nil, gofe.MalformedSecKey
	}
	// Secret key is a linear combination of input vector y
	// and master secret key SK.
	skY, err := SK.MulVec(y)
	if err != nil {
		return nil, gofe.MalformedInput
	}
	skY = skY.Mod(s.Params.Q)

	return skY, nil
}

// Encrypt encrypts vector x using public key PK.
// It returns the resulting ciphertext vector. In case of malformed
// public key or input vector that violates the configured bound,
// it returns an error.
func (s *LWE) Encrypt(x data.Vector, PK data.Matrix) (data.Vector, error) {
	if err := x.CheckBound(s.Params.BoundX); err != nil {
		return nil, err
	}
	if !PK.CheckDims(s.Params.M, s.Params.L) {
		return nil, gofe.MalformedPubKey
	}
	if len(x) != s.Params.L {
		return nil, gofe.MalformedInput
	}

	// Create a random vector comprised of m 0s and 1s
	r, err := data.NewRandomVector(s.Params.M, sample.NewBit())
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}

	// Ciphertext vectors will be composed of two vectors: ct0 and ctLast.
	// ct0 ... a vector comprising the first n elements of the cipher
	// ctLast ... a vector comprising the last l elements of the cipher

	// ct0 = A(transposed) * r
	ATrans := s.Params.A.Transpose()
	ct0, _ := ATrans.MulVec(r)

	// Calculate coordinates ct_last_i = <pkI, r> + t(xi) mod q
	// We can obtain the vector of dot products <pk_i, r> as PK(transposed) * r
	// Function t(x) is denoted as the center function
	PKTrans := PK.Transpose()
	ctLast, _ := PKTrans.MulVec(r)

	t := s.center(x)
	ctLast = ctLast.Add(t)
	ctLast = ctLast.Mod(s.Params.Q)

	// Construct the final ciphertext vector by joining both parts
	return append(ct0, ctLast...), nil
}

// Calculates the center function t(x) = floor(x*q/p) % q for a vector x.
func (s *LWE) center(v data.Vector) data.Vector {
	return v.Apply(func(x *big.Int) *big.Int {
		t := new(big.Int)
		t.Mul(x, s.Params.Q)
		t.Div(t, s.Params.P)
		t.Mod(t, s.Params.Q)

		return t
	})
}

// Decrypt accepts an encrypted vector ct, functional encryption key skY,
// and plaintext vector y. It returns the inner product of x and y.
// If decryption failed (for instance with input data that violates the
// configured bound or malformed ciphertext or keys), error is returned.
func (s *LWE) Decrypt(ct, skY, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if len(skY) != s.Params.N {
		return nil, gofe.MalformedDecKey
	}
	if len(y) != s.Params.L {
		return nil, gofe.MalformedInput
	}

	// Break down the ciphertext vector into
	// ct0     which holds first n elements of the cipher, and
	// ctLast  which holds last n elements of the cipher
	if len(ct) != s.Params.N+s.Params.L {
		return nil, gofe.MalformedCipher
	}
	ct0 := ct[:s.Params.N]
	ctLast := ct[s.Params.N:]

	// Calculate d = <y, ctLast> - <ct0, skY>
	yDotCtLast, _ := y.Dot(ctLast)
	yDotCtLast.Mod(yDotCtLast, s.Params.Q)
	ct0DotSkY, _ := ct0.Dot(skY)
	ct0DotSkY.Mod(ct0DotSkY, s.Params.Q)

	halfQ := new(big.Int).Div(s.Params.Q, big.NewInt(2))

	// d will hold the decrypted message
	d := new(big.Int).Sub(yDotCtLast, ct0DotSkY)
	d.Mod(d, s.Params.Q)
	// in case d > q/2 the result will be negative
	if d.Cmp(halfQ) == 1 {
		d.Sub(d, s.Params.Q)
	}

	d.Mul(d, s.Params.P)
	d.Add(d, halfQ)
	d.Div(d, s.Params.Q)
	return d, nil
}
