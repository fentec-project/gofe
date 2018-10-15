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

	"crypto/rand"

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
	boundX *big.Int
	// Inner product vector space size
	boundY *big.Int
	// Modulus for the resulting inner product.
	// K depends on the parameters l, P and V and is computed by the scheme.
	K *big.Int
	// Modulus for ciphertext and keys.
	// Must be significantly larger than K.
	// TODO check appropriateness of this parameter in constructor!
	q *big.Int
	// standard deviation for the noise terms in the encryption process
	sigmaQ *big.Float
	// standard deviation for first half of the matrix for sampling private key
	sigma1 *big.Float
	// standard deviation for second half of the matrix for sampling private key
	sigma2 *big.Float

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
// n and m, message space size boundX, inner product vector space size
// boundY.
//
// It returns an error in case public parameters of the scheme could
// not be generated.
func NewLWE(l, n int, boundX, boundY *big.Int) (*LWE, error) {

	// K = 2 * l * boundX * boundY
	K := new(big.Int).Mul(boundX, boundY)
	K.Mul(K, big.NewInt(int64(l*2)))

	nF := float64(n)

	nBitsQ := 1
	var sigma, sigma1, sigma2 *big.Float

	// parameters for the scheme are given as a set of requirements in the paper
	// hence we search for such parameters iteratively
	for i := 1; true; i++ {
		//assuming that the final q will have at most i bits we calculate a bound
		boundMF := float64(n * i)
		// tmp values
		log2M := math.Log2(boundMF)
		sqrtNLogM := math.Sqrt(nF * log2M)
		kF := new(big.Float).SetInt(K)
		kSquaredF := new(big.Float).Mul(kF, kF)

		max := new(big.Float)
		if kSquaredF.Cmp(big.NewFloat(boundMF)) == 1 {
			max.SetFloat64(boundMF)
		} else {
			max.Set(kSquaredF)
		}

		sqrtMax := new(big.Float).Sqrt(max)

		sigma1 = new(big.Float).Mul(big.NewFloat(sqrtNLogM), sqrtMax)
		// make it an integer for faster sampling using NormalDouble
		sigma1I, _ := sigma1.Int(nil)
		sigma1.SetInt(sigma1I)

		// tmp values
		nPow3 := math.Pow(nF, 3)
		powSqrtLogM5 := math.Pow(math.Sqrt(log2M), 5)
		mulVal := math.Sqrt(nF) * nPow3 * powSqrtLogM5 * math.Sqrt(boundMF)
		sigma2 = new(big.Float).Mul(big.NewFloat(mulVal), max)
		// make it an integer for faster sampling using NormalDouble
		sigma2I, _ := sigma2.Int(nil)
		sigma2.SetInt(sigma2I)

		// tmp value
		sigma1Square := new(big.Float).Mul(sigma1, sigma1)
		sigma2Square := new(big.Float).Mul(sigma2, sigma2)

		bound2 := new(big.Float).Add(sigma1Square, sigma2Square)
		bound2.Sqrt(bound2)
		bound2.Mul(bound2, big.NewFloat(math.Sqrt(nF)))

		sigma = new(big.Float).Quo(big.NewFloat(1), kSquaredF)
		sigma.Quo(sigma, bound2)
		sigma.Quo(sigma, big.NewFloat(math.Log2(nF)))

		// assuming number of bits of q will be at least nBitsQ from the previous
		// iteration (this is always true) we calculate sigma prime
		nfPow6 := math.Pow(nF, 6)
		nBitsQPow2 := math.Pow(float64(nBitsQ), 2)
		sqrtLog2nFPow5 := math.Pow(math.Sqrt(math.Log2(nF)), 5)
		sigmaPrime := new(big.Float).Quo(sigma, kF)
		sigmaPrime.Quo(sigmaPrime, big.NewFloat(nfPow6*nBitsQPow2*sqrtLog2nFPow5))

		boundForQ := new(big.Float)
		boundForQ.Quo(big.NewFloat(math.Sqrt(math.Log2(nF))), sigmaPrime)
		nBitsQ = boundForQ.MantExp(nil) + 1
		// check if the number of bits for q is greater than i as it was
		// assumed at the beginning of the iteration
		if nBitsQ < i {
			break
		}
		// in the next iteration the number of bits for q must be at least as
		// many as it was demanded in this iteration
		i = nBitsQ
	}
	// get q
	q, err := rand.Prime(rand.Reader, nBitsQ)
	if err != nil {
		return nil, errors.Wrap(err,
			"cannot generate parameters, generating a prime number failed")
	}

	m := int(1.01 * nF * float64(nBitsQ))

	// get sigmaQ
	qF := new(big.Float).SetInt(q)
	sigmaQ := new(big.Float).Mul(sigma, qF)
	// make it an integer for faster sampling using NormalDouble
	sigmaQI, _ := sigmaQ.Int(nil)
	sigmaQ.SetInt(sigmaQI)

	randMat, err := data.NewRandomMatrix(m, n, sample.NewUniform(q))
	if err != nil {
		return nil, errors.Wrap(err,
			"cannot generate parameters, generating a random matrix failed")
	}
	return &LWE{
		params: &lweParams{
			l:      l,
			n:      n,
			m:      m,
			boundX: boundX,
			boundY: boundY,
			q:      q,
			K:      K,
			sigmaQ: sigmaQ,
			sigma1: sigma1,
			sigma2: sigma2,
			A:      randMat,
		},
	}, nil
}

// GenerateSecretKey generates a secret key for the scheme.
// The secret key is a matrix with dimensions l*m.
//
// In case secret key could not be generated, it returns an error.
func (s *LWE) GenerateSecretKey() (data.Matrix, error) {
	var val *big.Int

	sampler1, err := sample.NewNormalDouble(s.params.sigma1, uint(s.params.n), big.NewFloat(1), true)
	if err != nil {
		return nil, errors.Wrap(err, "error generating secret key")
	}
	sampler2, err := sample.NewNormalDouble(s.params.sigma2, uint(s.params.n), big.NewFloat(1), true)
	if err != nil {
		return nil, errors.Wrap(err, "error generating secret key")
	}

	Z := make(data.Matrix, s.params.l)
	halfRows := Z.Rows() / 2
	for i := 0; i < Z.Rows(); i++ {
		Z[i] = make(data.Vector, s.params.m)
		for j := 0; j < Z.Cols(); j++ {
			if j < halfRows { // first half
				val, _ = sampler1.Sample()
			} else { // second half
				val, _ = sampler2.Sample()
				if j-halfRows == i {
					val.Add(val, big.NewInt(1))
				}
			}

			Z[i][j] = val
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

// DeriveKey accepts input vector y and master secret key Z, and derives a
// functional encryption key.
// In case of malformed secret key or input vector that violates the
// configured bound, it returns an error.
func (s *LWE) DeriveKey(y data.Vector, Z data.Matrix) (data.Vector, error) {
	if err := y.CheckBound(s.params.boundY); err != nil {
		return nil, err
	}
	if !Z.CheckDims(s.params.l, s.params.m) {
		return nil, gofe.MalformedSecKey
	}
	// Secret key is a linear combination of input vector x and master secret key Z.
	zY, err := Z.Transpose().MulVec(y)
	if err != nil {
		return nil, gofe.MalformedInput
	}
	zY = zY.Mod(s.params.q)

	return zY, nil
}

// Encrypt encrypts vector y using public key U.
// It returns the resulting ciphertext vector. In case of malformed
// public key or input vector that violates the configured bound,
// it returns an error.
func (s *LWE) Encrypt(x data.Vector, U data.Matrix) (data.Vector, error) {
	if err := x.CheckBound(s.params.boundX); err != nil {
		return nil, err
	}
	if !U.CheckDims(s.params.l, s.params.n) {
		return nil, gofe.MalformedPubKey
	}
	if len(x) != s.params.l {
		return nil, gofe.MalformedInput
	}

	// Create a random vector
	r, err := data.NewRandomVector(s.params.n, sample.NewUniform(s.params.q))
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}

	// calculate the standard distribution and sample vectors e0, e1
	sampler, err := sample.NewNormalDouble(s.params.sigmaQ, uint(s.params.n), big.NewFloat(1), true)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	e0, err0 := data.NewRandomVector(s.params.m, sampler)
	e1, err1 := data.NewRandomVector(s.params.l, sampler)
	if err0 != nil || err1 != nil {
		return nil, errors.Wrap(err0, "error in encrypt")
	}

	// calculate first part of the cipher
	c0, _ := s.params.A.MulVec(r)
	c0 = c0.Add(e0)
	c0 = c0.Mod(s.params.q)

	// calculate second part of the cipher
	qDivK := new(big.Int).Div(s.params.q, s.params.K)
	t := x.MulScalar(qDivK) // center

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
func (s *LWE) Decrypt(cipher, zY, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(s.params.boundY); err != nil {
		return nil, err
	}
	if len(zY) != s.params.m {
		return nil, gofe.MalformedDecKey
	}
	if len(y) != s.params.l {
		return nil, gofe.MalformedInput
	}

	if len(cipher) != s.params.m+s.params.l {
		return nil, gofe.MalformedCipher
	}
	c0 := cipher[:s.params.m]
	c1 := cipher[s.params.m:]
	yDotC1, _ := y.Dot(c1)
	zYDotC0, _ := zY.Dot(c0)

	mu1 := new(big.Int).Sub(yDotC1, zYDotC0)
	mu1.Mod(mu1, s.params.q)
	if mu1.Cmp(new(big.Int).Quo(s.params.q, big.NewInt(2))) == 1 {
		mu1.Sub(mu1, s.params.q)
	}
	// TODO Improve!
	kTimes2 := new(big.Int).Lsh(s.params.K, 1)
	qDivK := new(big.Int).Div(s.params.q, s.params.K)
	qDivKTimes2 := new(big.Int).Div(s.params.q, kTimes2)

	mu := new(big.Int).Add(mu1, qDivKTimes2)
	mu.Div(mu, qDivK)

	return mu, nil
}
