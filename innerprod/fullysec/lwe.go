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
	"math/big"

	"math"

	"github.com/fentec-project/gofe/data"
	gofe "github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"
)

// lweParams represents parameters for the fully secure LWE scheme.
type lweParams struct {
	l int // Length of data vectors for inner product

	n int // Main security parameters of the scheme
	m int // Number of samples

	// Message space size
	P *big.Int
	// Key space size
	V *big.Int
	// Modulus for the resulting inner product.
	// K depends on the parameters l, P and V and is computed by the scheme.
	K *big.Int
	// Modulus for ciphertext and keys.
	// Must be significantly larger than K.
	// TODO check appropriateness of this parameter in constructor!
	q *big.Int

	// Matrix A of dimensions m*n is a public parameter
	// of the scheme
	A data.Matrix
}

// LWE represents a scheme instantiated from the LWE problem.
type LWE struct {
	params *lweParams
}

// NewLWE configures a new instance of the scheme.
// It accepts the length of input vectors l, the main security parameters
// n and m, message space size P, key and ciphertext space size V, and
// modulus for ciphertext and keys q.
//
// It returns an error in case public parameters of the scheme could
// not be generated.
func NewLWE(l, n, m int, P, V, q *big.Int) (*LWE, error) {
	randMat, err := data.NewRandomMatrix(m, n, sample.NewUniform(q))
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate public parameters")
	}

	// K = l * P * V
	K := new(big.Int).Mul(P, V)
	K.Mul(K, big.NewInt(int64(l)))

	return &LWE{
		params: &lweParams{
			l: l,
			n: n,
			m: m,
			P: P,
			V: V,
			q: q,
			K: K,
			A: randMat,
		},
	}, nil
}

// GenerateSecretKey accepts precision eps and a limit k for the
// sampling interval, and generates a secret key for the scheme.
// The secret key is a matrix with dimensions l*m.
//
// In case secret key could not be generated, it returns an error.
func (s *LWE) GenerateSecretKey(eps, k float64) (data.Matrix, error) {
	var x *big.Int

	nF := float64(s.params.n)
	mF := float64(s.params.m)

	// standard deviation for first half of the matrix
	log2M := math.Log2(mF)
	sqrtNLogM := math.Sqrt(nF * log2M)
	kSquared := new(big.Int).Mul(s.params.K, s.params.K).Int64() // accuracy?
	max := math.Max(mF, float64(kSquared))
	sqrtMax := math.Sqrt(max)
	sigma1 := sqrtNLogM * sqrtMax
	sampler1 := sample.NewNormal(sigma1, eps, k)

	// standard deviation for second half of the matrix
	nPow3 := math.Pow(nF, 3)
	powSqrtLogM5 := math.Pow(math.Sqrt(log2M), 5)
	sigma2 := math.Sqrt(nF) * nPow3 * max * log2M * powSqrtLogM5
	sampler2 := sample.NewNormal(sigma2, eps, k)

	Z := make(data.Matrix, s.params.l)
	halfRows := Z.Rows() / 2
	for i := 0; i < Z.Rows(); i++ {
		Z[i] = make(data.Vector, s.params.m)
		for j := 0; j < Z.Cols(); j++ {
			if j < halfRows { // first half
				x, _ = sampler1.Sample()
			} else { // second half
				x, _ = sampler2.Sample()
				if j-halfRows == i {
					x.Add(x, big.NewInt(1))
				}
			}

			Z[i][j] = x
		}
	}

	return Z, nil
}

// GeneratePublicKey accepts a master secret key Z and generates a
// corresponding master public key.
// Public key is a matrix of l*m elements.
// In case of a malformed secret key the function returns an error.
func (s *LWE) GeneratePublicKey(Z data.Matrix) (data.Matrix, error) {
	if !Z.CheckDims(s.params.l, s.params.m) {
		return nil, gofe.MalformedSecKey
	}
	// public key is obtained by multiplying secret key Z by a random matrix A.
	U, _ := Z.Mul(s.params.A)
	U = U.Mod(s.params.q)

	return U, nil
}

// DeriveKey accepts input vector x and master secret key Z, and derives a
// functional encryption key.
// In case of malformed secret key or input vector that violates the
// configured bound, it returns an error.
func (s *LWE) DeriveKey(x data.Vector, Z data.Matrix) (data.Vector, error) {
	if err := x.CheckBound(s.params.V); err != nil {
		return nil, err
	}
	if !Z.CheckDims(s.params.l, s.params.m) {
		return nil, gofe.MalformedSecKey
	}
	// Secret key is a linear combination of input vector x and master secret key Z.
	zX, err := Z.Transpose().MulVec(x)
	if err != nil {
		return nil, gofe.MalformedInput
	}
	zX = zX.Mod(s.params.q)

	return zX, nil
}

// Encrypt encrypts vector y using public key U.
// It returns the resulting ciphertext vector. In case of malformed
// public key or input vector that violates the configured bound,
// it returns an error.
func (s *LWE) Encrypt(y data.Vector, U data.Matrix, alpha *big.Float, eps, k float64) (data.Vector, error) {
	if err := y.CheckBound(s.params.P); err != nil {
		return nil, err
	}
	if !U.CheckDims(s.params.l, s.params.n) {
		return nil, gofe.MalformedPubKey
	}
	if len(y) != s.params.l {
		return nil, gofe.MalformedInput
	}

	// Create a random vector
	r, err := data.NewRandomVector(s.params.n, sample.NewUniform(s.params.q))
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}

	// calculate the standard distribution and sample vectors e0, e1
	q := new(big.Float).SetInt(s.params.q)
	alphaQ, _ := new(big.Float).Mul(alpha, q).Float64() // check accuracy TODO
	sampler := sample.NewNormal(alphaQ, eps, k)
	e0, err0 := data.NewRandomVector(s.params.m, sampler)
	e1, err1 := data.NewRandomVector(s.params.l, sampler)
	if err0 != nil || err1 != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}

	// calculate first part of the cipher
	c0, _ := s.params.A.MulVec(r)
	c0 = c0.Add(e0)
	c0 = c0.Mod(s.params.q)

	// calculate second part of the cipher
	qDivK := new(big.Int).Div(s.params.q, s.params.K)
	t := y.MulScalar(qDivK) // center

	c1, _ := U.MulVec(r)
	c1 = c1.Add(e1)
	c1 = c1.Add(t)
	c1 = c1.Mod(s.params.q)

	return append(c0, c1...), nil
}

// Decrypt accepts an encrypted vector cipher, functional encryption key zX,
// and plaintext vector x, and calculates the inner product of x and y.
// If decryption failed (for instance with input data that violates the
// configured bound or malformed ciphertext or keys), error is returned.
func (s *LWE) Decrypt(cipher, zX, x data.Vector) (*big.Int, error) {
	if err := x.CheckBound(s.params.V); err != nil {
		return nil, err
	}
	if len(zX) != s.params.m {
		return nil, gofe.MalformedDecKey
	}
	if len(x) != s.params.l {
		return nil, gofe.MalformedInput
	}

	if len(cipher) != s.params.m+s.params.l {
		return nil, gofe.MalformedCipher
	}
	c0 := cipher[:s.params.m]
	c1 := cipher[s.params.m:]
	xDotC1, _ := x.Dot(c1)
	zXDotC0, _ := zX.Dot(c0)

	mu1 := new(big.Int).Sub(xDotC1, zXDotC0)
	mu1.Mod(mu1, s.params.q)

	// TODO Improve!
	kTimes2 := new(big.Int).Lsh(s.params.K, 1)
	qDivK := new(big.Int).Div(s.params.q, s.params.K)
	qDivKTimes2 := new(big.Int).Div(s.params.q, kTimes2)

	mu := new(big.Int).Add(mu1, qDivKTimes2)
	mu.Div(mu, qDivK)
	mu.Mod(mu, s.params.K)

	return mu, nil
}
