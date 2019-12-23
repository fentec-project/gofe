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
	"math"
	"math/big"

	"github.com/fentec-project/gofe/data"
	gofe "github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"
)

// LWEParams represents parameters for the fully secure LWE scheme.
type LWEParams struct {
	L int // Length of data vectors for inner product

	N int // Main security parameters of the scheme
	M int // Number of samples

	BoundX *big.Int // Message space size
	BoundY *big.Int // Inner product vector space size

	// Modulus for the resulting inner product.
	// K depends on the parameters L, P and V and is computed by the scheme.
	K *big.Int

	// Modulus for ciphertext and keys.
	// Must be significantly larger than K.
	// TODO check appropriateness of this parameter in constructor!
	Q *big.Int

	// standard deviation for the noise terms in the encryption process
	SigmaQ *big.Float
	// precomputed LSigmaQ = SigmaQ / (1/2log(2)) needed for sampling
	LSigmaQ *big.Int
	// standard deviation for first half of the matrix for sampling private key
	Sigma1 *big.Float
	// precomputed LSigma1 = Sigma1 / (1/2log(2)) needed for sampling
	LSigma1 *big.Int
	// standard deviation for second half of the matrix for sampling private key
	Sigma2 *big.Float
	// precomputed LSigma2 = Sigma2 / (1/2log(2)) needed for sampling
	LSigma2 *big.Int
	// Matrix A of dimensions M*N is a public parameter of the scheme
	A data.Matrix
}

// LWE represents a scheme instantiated from the LWE problem.
// Based on the LWE variant of:
// Agrawal, Shweta, Libert, and Stehle:
// "Fully secure functional encryption for inner products,
// from standard assumptions".
type LWE struct {
	Params *LWEParams
}

// NewLWE configures a new instance of the scheme.
// It accepts the length of input vectors l, the main security parameter
// n, the message space size boundX, and the inner product vector space size
// boundY. The function sets up the remaining public parameters as
// it is suggested in the paper by Agrawal, Shweta, Libert, and Stehle:
// "Fully secure functional encryption for inner products,
// from standard assumptions".
// Note that this is a prototype implementation and should not be
// used in production before security testing against various
// known attacks has been performed. Unfortunately, no such (theoretical)
// evaluation exists yet in the literature.
//
// It returns an error in case public parameters of the scheme could
// not be generated.
func NewLWE(l, n int, boundX, boundY *big.Int) (*LWE, error) {

	// K = 2 * l * boundX * boundY
	K := new(big.Int).Mul(boundX, boundY)
	K.Mul(K, big.NewInt(int64(l*2)))
	kF := new(big.Float).SetInt(K)
	SquaredF := new(big.Float).Mul(kF, kF)

	nF := float64(n)

	nBitsQ := 1
	var sigma, sigma1, sigma2 *big.Float
	var lSigma1, lSigma2 *big.Int
	// parameters for the scheme are given as a set of requirements in the paper
	// hence we search for such parameters iteratively
	for i := 1; true; i++ {
		//assuming that the final q will have at most i bits we calculate a bound
		boundMF := float64(n * i)
		// tmp values
		log2M := math.Log2(boundMF)
		sqrtNLogM := math.Sqrt(nF * log2M)

		max := new(big.Float)
		if SquaredF.Cmp(big.NewFloat(boundMF)) == 1 {
			max.SetFloat64(boundMF)
		} else {
			max.Set(SquaredF)
		}

		sqrtMax := new(big.Float).Sqrt(max)

		sigma1 = new(big.Float).Mul(big.NewFloat(sqrtNLogM), sqrtMax)
		// to sample with NormalDoubleConstant sigmaQ must be
		// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
		// it such
		lSigma1F := new(big.Float).Quo(sigma1, sample.SigmaCDT)
		lSigma1, _ = lSigma1F.Int(nil)
		sigma1.Mul(sample.SigmaCDT, lSigma1F)

		// tmp values
		nPow3 := math.Pow(nF, 3)
		powSqrtLogM5 := math.Pow(math.Sqrt(log2M), 5)
		mulVal := math.Sqrt(nF) * nPow3 * powSqrtLogM5 * math.Sqrt(boundMF)
		sigma2 = new(big.Float).Mul(big.NewFloat(mulVal), max)
		// to sample with NormalDoubleConstant sigmaQ must be
		// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
		// it such
		lSigma2F := new(big.Float).Quo(sigma2, sample.SigmaCDT)
		lSigma2, _ = lSigma2F.Int(nil)
		sigma2.Mul(sample.SigmaCDT, lSigma2F)

		// tmp value
		sigma1Square := new(big.Float).Mul(sigma1, sigma1)
		sigma2Square := new(big.Float).Mul(sigma2, sigma2)

		bound2 := new(big.Float).Add(sigma1Square, sigma2Square)
		bound2.Sqrt(bound2)
		bound2.Mul(bound2, big.NewFloat(math.Sqrt(nF)))

		sigma = new(big.Float).Quo(big.NewFloat(1), SquaredF)
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
		return nil, err
	}

	m := int(1.01 * nF * float64(nBitsQ))

	// get sigmaQ
	qF := new(big.Float).SetInt(q)
	sigmaQ := new(big.Float).Mul(sigma, qF)
	// to sample with NormalDoubleConstant sigmaQ must be
	// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
	// it such
	lSigmaQF := new(big.Float).Quo(sigmaQ, sample.SigmaCDT)
	lSigmaQ, _ := lSigmaQF.Int(nil)
	sigmaQ.Mul(sample.SigmaCDT, lSigmaQF)

	randMat, err := data.NewRandomMatrix(m, n, sample.NewUniform(q))
	if err != nil {
		return nil, err
	}
	return &LWE{
		Params: &LWEParams{
			L:       l,
			N:       n,
			M:       m,
			BoundX:  boundX,
			BoundY:  boundY,
			Q:       q,
			K:       K,
			SigmaQ:  sigmaQ,
			LSigmaQ: lSigmaQ,
			Sigma1:  sigma1,
			LSigma1: lSigma1,
			Sigma2:  sigma2,
			LSigma2: lSigma2,
			A:       randMat,
		},
	}, nil
}

// GenerateSecretKey generates a secret key for the scheme.
// The secret key is a matrix with dimensions l*m.
//
// In case secret key could not be generated, it returns an error.
func (s *LWE) GenerateSecretKey() (data.Matrix, error) {
	var val *big.Int

	sampler1 := sample.NewNormalDoubleConstant(s.Params.LSigma1)
	sampler2 := sample.NewNormalDoubleConstant(s.Params.LSigma2)

	Z := make(data.Matrix, s.Params.L)
	halfRows := Z.Rows() / 2
	for i := 0; i < Z.Rows(); i++ {
		Z[i] = make(data.Vector, s.Params.M)
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
	if !Z.CheckDims(s.Params.L, s.Params.M) {
		return nil, gofe.ErrMalformedSecKey
	}
	// public key is obtained by multiplying secret key Z by a random matrix A.
	U, _ := Z.Mul(s.Params.A)
	U = U.Mod(s.Params.Q)

	return U, nil
}

// DeriveKey accepts input vector y and master secret key Z, and derives a
// functional encryption key.
// In case of malformed secret key or input vector that violates the
// configured bound, it returns an error.
func (s *LWE) DeriveKey(y data.Vector, Z data.Matrix) (data.Vector, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if !Z.CheckDims(s.Params.L, s.Params.M) {
		return nil, gofe.ErrMalformedSecKey
	}
	// Secret key is a linear combination of input vector x and master secret key Z.
	zY, err := Z.Transpose().MulVec(y)
	if err != nil {
		return nil, gofe.ErrMalformedInput
	}
	zY = zY.Mod(s.Params.Q)

	return zY, nil
}

// Encrypt encrypts vector y using public key U.
// It returns the resulting ciphertext vector. In case of malformed
// public key or input vector that violates the configured bound,
// it returns an error.
func (s *LWE) Encrypt(x data.Vector, U data.Matrix) (data.Vector, error) {
	if err := x.CheckBound(s.Params.BoundX); err != nil {
		return nil, err
	}
	if !U.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.ErrMalformedPubKey
	}
	if len(x) != s.Params.L {
		return nil, gofe.ErrMalformedInput
	}

	// Create a random vector
	r, err := data.NewRandomVector(s.Params.N, sample.NewUniform(s.Params.Q))
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}

	// calculate the standard distribution and sample vectors e0, e1
	sampler := sample.NewNormalDoubleConstant(s.Params.LSigmaQ)

	e0, err0 := data.NewRandomVector(s.Params.M, sampler)
	e1, err1 := data.NewRandomVector(s.Params.L, sampler)
	if err0 != nil || err1 != nil {
		return nil, errors.Wrap(err0, "error in encrypt")
	}

	// calculate first part of the cipher
	c0, _ := s.Params.A.MulVec(r)
	c0 = c0.Add(e0)
	c0 = c0.Mod(s.Params.Q)

	// calculate second part of the cipher
	qDivK := new(big.Int).Div(s.Params.Q, s.Params.K)
	t := x.MulScalar(qDivK) // center

	c1, _ := U.MulVec(r)
	c1 = c1.Add(e1)
	c1 = c1.Add(t)
	c1 = c1.Mod(s.Params.Q)

	return append(c0, c1...), nil
}

// Decrypt accepts an encrypted vector cipher, functional encryption key zX,
// and plaintext vector x, and calculates the inner product of x and y.
// If decryption failed (for instance with input data that violates the
// configured bound or malformed ciphertext or keys), error is returned.
func (s *LWE) Decrypt(cipher, zY, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if len(zY) != s.Params.M {
		return nil, gofe.ErrMalformedDecKey
	}
	if len(y) != s.Params.L {
		return nil, gofe.ErrMalformedInput
	}

	if len(cipher) != s.Params.M+s.Params.L {
		return nil, gofe.ErrMalformedCipher
	}
	c0 := cipher[:s.Params.M]
	c1 := cipher[s.Params.M:]
	yDotC1, _ := y.Dot(c1)
	zYDotC0, _ := zY.Dot(c0)

	mu1 := new(big.Int).Sub(yDotC1, zYDotC0)
	mu1.Mod(mu1, s.Params.Q)
	if mu1.Cmp(new(big.Int).Quo(s.Params.Q, big.NewInt(2))) == 1 {
		mu1.Sub(mu1, s.Params.Q)
	}

	paramsKTimes2 := new(big.Int).Lsh(s.Params.K, 1)
	qDivK := new(big.Int).Div(s.Params.Q, s.Params.K)
	qDivKTimes2 := new(big.Int).Div(s.Params.Q, paramsKTimes2)

	mu := new(big.Int).Add(mu1, qDivKTimes2)
	mu.Div(mu, qDivK)

	return mu, nil
}
