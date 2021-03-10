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
	gofe "github.com/fentec-project/gofe/internal"
	"math"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"
)

// RingLWEParams represents parameters for the ring LWE scheme.
type RingLWEParams struct {
	L int // Length of data vectors for inner product

	// Main security parameters of the scheme
	N int

	// Settings for discrete gaussian sampler
	Sigma1 *big.Float // standard deviation
	Sigma2 *big.Float // standard deviation
	Sigma3 *big.Float // standard deviation

	BoundX *big.Int // upper bound for coordinates of input vectors
	BoundY *big.Int // upper bound for coordinates of inner-product vectors

	P *big.Int // bound for the resulting inner product
	Q *big.Int // modulus for ciphertext and keys

	// A is a vector with N coordinates.
	// It represents a random polynomial for the scheme.
	A data.Vector
}

// RingLWE represents a FE scheme instantiated from the ringLWE assumption. It
// allows to encrypt a matrix X and derive a FE based on a vector y, so that
// one can decrypt y^T * X and nothing else. This can be seen as a SIMD version
// of a simple inner product scheme, since multiple vectors (columns of X) can be
// multiplied with y at the same time.
// It is based on
// Bermudo Mera, Karmakar, Marc, and Soleimanian:
// "Efficient Lattice-Based Inner-Product Functional Encryption",
// see https://eprint.iacr.org/2021/046.
type RingLWE struct {
	Params  *RingLWEParams
}

// NewRingLWE configures a new instance of the scheme.
// It accepts a security parameter sec, the length of input vectors l,
// bound for coordinates of input vectors x and y. It generates all the
// parameters needed to have a scheme with at least sec bits of security
// by using all the bounds derived in the paper https://eprint.iacr.org/2021/046,
// as well as having the parameters secure against so called primal attack
// on LWE.
func NewRingLWE(sec, l int, boundX, boundY *big.Int) (*RingLWE, error) {
	K := new(big.Int).Mul(boundX, boundY)
	K.Mul(K, big.NewInt(int64(2*l)))

	kappa := big.NewFloat(float64(sec))
	kappaSqrt := new(big.Float).Sqrt(kappa)

	sigma := big.NewFloat(1)
	sigma1 := new(big.Float).Mul(big.NewFloat(math.Sqrt(float64(4*l))), sigma)
	sigma1.Mul(sigma1, new(big.Float).SetInt(boundX))
	var q *big.Int
	var sigma2, sigma3 *big.Float
	var safe bool
	var n int
	boundOfB := float64(sec) / 0.265
	for pow := 6; pow < 20; pow++ {
		n = 1 << uint(pow)

		sigma2 = new(big.Float).Mul(big.NewFloat(math.Sqrt(float64(2*(l+2)*n*n))), sigma)
		sigma2.Mul(sigma2, sigma1)
		sigma2.Mul(sigma2, kappaSqrt)

		sigma3 = new(big.Float).Mul(sigma2, big.NewFloat(math.Sqrt(float64(2))))

		qFloat1 := new(big.Float).Mul(sigma1, sigma2)
		qFloat1.Mul(qFloat1, kappa)
		qFloat1.Mul(qFloat1, big.NewFloat(float64(2*n)))
		qFloat2 := new(big.Float).Mul(kappaSqrt, sigma3)
		qFloat := new(big.Float).Add(qFloat1, qFloat2)
		qFloat.Mul(qFloat, new(big.Float).SetInt(boundY))
		qFloat.Mul(qFloat, big.NewFloat(float64(2*l)))

		q, _ = qFloat.Int(nil)
		q.Mul(q, K)

		qF := new(big.Float).SetInt(q)
		qFF, _ := qF.Float64()
		sigmaPrimeQF, _ := sigma.Float64()

		safe = true
		for b := float64(50); b <= boundOfB; b = b + 1 {
			for m := int(math.Max(1, b-float64(n))); m < 3*n; m++ {
				delta := math.Pow(math.Pow(math.Pi*b, 1/b)*b/(2*math.Pi*math.E), 1./(2.*b-2.))
				left := sigmaPrimeQF * math.Sqrt(b)
				d := n + m
				right := math.Pow(delta, 2*b-float64(d)-1) * math.Pow(qFF, float64(m)/float64(d))
				if left < right {
					safe = false
					break
				}
			}
			if safe == false {
				break
			}
		}
		if safe {
			break
		}
	}

	randVec, err := data.NewRandomVector(n, sample.NewUniform(q))
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate random polynomial")
	}

	return &RingLWE{
		Params: &RingLWEParams{
			L:     l,
			N:     n,
			BoundX: boundX,
			BoundY: boundY,
			P:     K,
			Q:     q,
			Sigma1: sigma1,
			Sigma2: sigma2,
			Sigma3: sigma3,
			A:     randVec,
		},
	}, nil
}

// GenerateSecretKey generates a secret key for the scheme.
// The key is a matrix of l*n small elements sampled from
// Discrete Gaussian distribution.
//
// In case secret key could not be generated, it returns an error.
func (s *RingLWE) GenerateSecretKey() (data.Matrix, error) {
	lSigmaF := new(big.Float).Quo(s.Params.Sigma1, sample.SigmaCDT)
	lSigma, _ := lSigmaF.Int(nil)
	sampler := sample.NewNormalDoubleConstant(lSigma)
	return data.NewRandomMatrix(s.Params.L, s.Params.N, sampler)
}

// GeneratePublicKey accepts a master secret key SK and generates a
// corresponding master public key.
// Public key is a matrix of l*n elements.
// In case of a malformed secret key the function returns an error.
func (s *RingLWE) GeneratePublicKey(SK data.Matrix) (data.Matrix, error) {
	if !SK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.ErrMalformedPubKey
	}
	// Generate noise matrix
	// Elements are sampled from the same distribution as the secret key S.
	lSigmaF := new(big.Float).Quo(s.Params.Sigma1, sample.SigmaCDT)
	lSigma, _ := lSigmaF.Int(nil)
	sampler := sample.NewNormalDoubleConstant(lSigma)
	E, err := data.NewRandomMatrix(s.Params.L, s.Params.N, sampler)
	if err != nil {
		return nil, errors.Wrap(err, "public key generation failed")
	}

	// Calculate public key PK row by row as PKi = (a * SKi + Ei) % q.
	// Multiplication and addition are in the ring of polynomials
	PK := make(data.Matrix, s.Params.L)
	for i := 0; i < PK.Rows(); i++ {
		pkI, _ := SK[i].MulAsPolyInRing(s.Params.A)
		pkI = pkI.Add(E[i])
		PK[i] = pkI
	}
	PK = PK.Mod(s.Params.Q)

	return PK, nil
}

// DeriveKey accepts input vector y and master secret key SK, and derives a
// functional encryption key.
// In case of malformed secret key or input vector that violates the
// configured bound, it returns an error.
func (s *RingLWE) DeriveKey(y data.Vector, SK data.Matrix) (data.Vector, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if !SK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.ErrMalformedSecKey
	}
	// Secret key is a linear combination of input vector y and master secret keys.
	SKTrans := SK.Transpose()
	skY, err := SKTrans.MulVec(y)
	if err != nil {
		return nil, gofe.ErrMalformedInput
	}
	skY = skY.Mod(s.Params.Q)

	return skY, nil
}

// Calculates the center function t(x) = floor(x*q/p) % q for a matrix X and
// place it in a bigger matrix.
func (s *RingLWE) center(X data.Matrix) data.Matrix {
	ret := data.NewConstantMatrix(s.Params.L, s.Params.N, big.NewInt(0))

	for i := 0; i < X.Rows(); i++ {
		for j := 0; j < X.Cols(); j++ {
			ret[i][j].Mul(X[i][j], s.Params.Q)
			ret[i][j].Div(ret[i][j], s.Params.P)
			ret[i][j].Mod(ret[i][j], s.Params.Q)
		}
	}

	return ret
}

// RingLWECipher is functional encryption key for DDH Scheme.
type RingLWECipher struct {
	Ct0   data.Matrix
	Ct1   data.Vector
	K    int
}

// Encrypt encrypts matrix X using public key PK.
// It returns the resulting ciphertext matrix. In case of malformed
// public key or input matrix that violates the configured bound,
// it returns an error.
//
//The resulting ciphertext has dimensions (l + 1) * n.
func (s *RingLWE) Encrypt(X data.Matrix, PK data.Matrix) (*RingLWECipher, error) {
	if err := X.CheckBound(s.Params.BoundX); err != nil {
		return nil, err
	}

	if !PK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.ErrMalformedPubKey
	}
	if !(X.Rows() == s.Params.L && X.Cols() <= s.Params.N) {
		return nil, gofe.ErrMalformedInput
	}

	// Create a small random vector r
	lSigma2F := new(big.Float).Quo(s.Params.Sigma2, sample.SigmaCDT)
	lSigma2, _ := lSigma2F.Int(nil)
	sampler2 := sample.NewNormalDoubleConstant(lSigma2)
	r, err := data.NewRandomVector(s.Params.N, sampler2)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	// Create noise matrix E to secure the encryption
	lSigma3F := new(big.Float).Quo(s.Params.Sigma3, sample.SigmaCDT)
	lSigma3, _ := lSigma3F.Int(nil)
	sampler3 := sample.NewNormalDoubleConstant(lSigma3)
	E, err := data.NewRandomMatrix(s.Params.L, s.Params.N, sampler3)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	// Calculate cipher CT row by row as CTi = (PKi * r + Ei) % q.
	// Multiplication and addition are in the ring of polynomials.
	CT0 := make(data.Matrix, s.Params.L)
	for i := 0; i < CT0.Rows(); i++ {
		CT0i, _ := PK[i].MulAsPolyInRing(r)
		CT0i = CT0i.Add(E[i])
		CT0[i] = CT0i
	}
	CT0 = CT0.Mod(s.Params.Q)

	// Include the message X in the encryption
	T := s.center(X)
	CT0, _ = CT0.Add(T)
	CT0 = CT0.Mod(s.Params.Q)

	// Construct the last row of the cipher
	ct1, _ := s.Params.A.MulAsPolyInRing(r)
	e, err := data.NewRandomVector(s.Params.N, sampler2)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	ct1 = ct1.Add(e)
	ct1 = ct1.Mod(s.Params.Q)

	res := &RingLWECipher{Ct0: CT0, Ct1: ct1, K: X.Cols()}

	return res, nil
}

// Decrypt accepts a ciphertext CT, secret key skY, and plaintext
// vector y, and returns a vector of inner products of X's rows and y.
// If decryption failed (for instance with input data that violates the
// configured bound or malformed ciphertext or keys), error is returned.
func (s *RingLWE) Decrypt(CT *RingLWECipher, skY, y data.Vector) (data.Vector, error) {
	if err := y.CheckBound(s.Params.BoundY); err != nil {
		return nil, err
	}
	if len(skY) != s.Params.N {
		return nil, gofe.ErrMalformedDecKey
	}
	if len(y) != s.Params.L {
		return nil, gofe.ErrMalformedInput
	}

	if !CT.Ct0.CheckDims(s.Params.L, s.Params.N) || len(CT.Ct1) != s.Params.N {
		return nil, gofe.ErrMalformedCipher
	}
	CT0 := CT.Ct0
	ct1 := CT.Ct1

	CT0Trans := CT0.Transpose()
	CT0TransMulY, _ := CT0Trans.MulVec(y)
	CT0TransMulY = CT0TransMulY.Mod(s.Params.Q)

	ct1MulSkY, _ := ct1.MulAsPolyInRing(skY)
	ct1MulSkY = ct1MulSkY.Apply(func(x *big.Int) *big.Int {
		return new(big.Int).Neg(x)
	})

	d := CT0TransMulY.Add(ct1MulSkY)
	d = d.Mod(s.Params.Q)
	halfQ := new(big.Int).Div(s.Params.Q, big.NewInt(2))

	d = d.Apply(func(x *big.Int) *big.Int {
		if x.Cmp(halfQ) == 1 {
			x.Sub(x, s.Params.Q)
		}
		x.Mul(x, s.Params.P)
		x.Add(x, halfQ)
		x.Div(x, s.Params.Q)

		return x
	})

	return d[:CT.K], nil
}
