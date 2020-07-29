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
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/sample"
)

// PaillierMulti represents a multi input variant of the
// underlying Paillier scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
// The participants in the scheme are clients and a central authority.
// The central authority generates keys for each client so that client i
// encrypts vector x_i. The scheme allows the central authority to
// generate a key_Y, depending on a matrix Y with rows y_i, so that
// given key_y and the ciphertext the decryptor can compute value
// Σ_i <x_i, y_i> (sum of dot products).

// PaillierMulti is a struct in PaillierMulti scheme, that holds
// all the shared parameters, and can represent the central authority
// or the decryptor.
type PaillierMulti struct {
	NumClients int
	BoundX      *big.Int
	BoundY      *big.Int
	*Paillier
}

// DamgardMultiClient represents a single client for the PaillierMulti scheme.
type PaillierMultiClient struct {
	BoundX      *big.Int
	BoundY      *big.Int
	*Paillier
}

// NewPaillierMulti configures a new instance of the scheme.
// It accepts the number of clients, the length of
// input vectors l, security parameter lambda (for number of
// bits of security the bit length of primes p and q to be generated
// (the scheme is operating in the Z_{(pq)^2} group), and a bound by
// which coordinates of input vectors are bounded. It generates all
//the remaining parameters to be shared.
//
// It returns an error in case the underlying Paillier scheme
// instances could not be properly instantiated.
func NewPaillierMulti(numClients, l, lambda, bitLength int, boundX, boundY *big.Int) (*PaillierMulti, error) {
	var newBoundX *big.Int
	newBoundX = nil
	if boundX != nil && boundY != nil {
		newBoundX = new(big.Int).Mul(boundX, big.NewInt(3))
	}
	paillier, err := NewPaillier(l, lambda, bitLength, newBoundX, boundY)
	if err != nil {
		return nil, err
	}

	// the bound of the underlying Damgard scheme is set to
	// the maximum value since the scheme will be used to encrypt
	// values summed with one time pad, thus arbitrary big
	paillier.Params.BoundX = nil
	paillier.Params.BoundY = nil

	return &PaillierMulti{
		NumClients: numClients,
		BoundY: boundY,
		BoundX: boundX,
		Paillier:    paillier,
	}, nil
}


// NewPaillierMultiClientFromParams takes the bound and configuration parameters of an underlying
// Paillier scheme instance, and instantiates a new PaillierMultiClient.
//
// It returns a new PaillierMultiClient instance.
func NewPaillierMultiClientFromParams(params *PaillierParams, boundX, boundY *big.Int) *PaillierMultiClient {
	return &PaillierMultiClient{
		BoundY: boundY,
		BoundX: boundX,
		Paillier: &Paillier{params},
	}
}

// NewPaillierMultiFromParams takes the number of clients, bound and configuration
// parameters of an existing Paillier scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new PaillierMulti instance.
func NewPaillierMultiFromParams(numClients int, boundX, boundY *big.Int, params *PaillierParams) *PaillierMulti {
	return &PaillierMulti{
		NumClients: numClients,
		BoundX: boundX,
		BoundY: boundY,
		Paillier:    &Paillier{params},
	}
}

// PaillierMultiSecKeys is a struct containing keys and one time pads for all the clients in
// the Paillier multi input scheme.
type PaillierMultiSecKeys struct {
	Msk data.Matrix
	Mpk data.Matrix
	Otp data.Matrix
}

// GenerateMasterKeys generates keys and one time pads for all the clients.
//
// It returns an error in case values could not be generated.
func (dm *PaillierMulti) GenerateMasterKeys() (*PaillierMultiSecKeys, error) {
	multiMsk := make([]data.Vector, dm.NumClients)
	multiMpk := make([]data.Vector, dm.NumClients)
	multiOtp := make([]data.Vector, dm.NumClients)

	for i := 0; i < dm.NumClients; i++ {
		msk, mpk, err := dm.Paillier.GenerateMasterKeys()
		if err != nil {
			return nil, fmt.Errorf("error in master key generation")
		}
		multiMsk[i] = msk
		multiMpk[i] = mpk

		otp, err := data.NewRandomVector(dm.Params.L, sample.NewUniform(dm.Params.NSquare))
		if err != nil {
			return nil, fmt.Errorf("error in random vector generation")
		}
		multiOtp[i] = otp
	}
	secKeys := &PaillierMultiSecKeys{
		Msk: data.Matrix(multiMsk),
		Mpk: data.Matrix(multiMpk),
		Otp: data.Matrix(multiOtp),
	}

	return secKeys, nil
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key of the underlying Paillier scheme and
// one-time pad otp (which are a part of the secret key). It returns
// the ciphertext vector. If the encryption failed, error is returned.
func (e *PaillierMultiClient) Encrypt(x data.Vector, pubKey, otp data.Vector) (data.Vector, error) {
	if e.BoundX != nil {
		if err := x.CheckBound(e.BoundX); err != nil {
			return nil, err
		}
	}

	xAddOtp := x.Add(otp)
	xAddOtp = xAddOtp.Mod(e.Params.NSquare)

	return e.Paillier.Encrypt(xAddOtp, pubKey)
}

// PaillierMultiDerivedKey is a functional encryption key for PaillierMulti scheme.
type PaillierMultiDerivedKey struct {
	Keys []*big.Int
	Z    *big.Int // Σ <u_i, y_i> where u_i is OTP key for i-th client
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *PaillierMulti) DeriveKey(secKey *PaillierMultiSecKeys, y data.Matrix) (*PaillierMultiDerivedKey, error) {
	if dm.BoundY != nil {
		if err := y.CheckBound(dm.BoundY); err != nil {
			return nil, err
		}
	}
	z, err := secKey.Otp.Dot(y)
	if err != nil {
		return nil, err
	}
	z.Mod(z, dm.Params.NSquare)

	derivedKeys := make([]*big.Int, dm.NumClients)
	for i := 0; i < dm.NumClients; i++ {
		derivedKey, err := dm.Paillier.DeriveKey(secKey.Msk[i], y[i])
		if err != nil {
			return nil, err
		}
		derivedKeys[i] = derivedKey
	}

	return &PaillierMultiDerivedKey{derivedKeys, z}, nil
}

// Decrypt accepts an array of ciphers, i.e. an array of encrypted vectors,
// functional encryption key, and a matrix y describing the inner-product.
// It returns the sum of inner products Σ_i <x_i, y_i>.
// If decryption failed, error is returned.
func (dm *PaillierMulti) Decrypt(cipher []data.Vector, key *PaillierMultiDerivedKey, y data.Matrix) (*big.Int, error) {
	if dm.BoundY != nil {
		if err := y.CheckBound(dm.BoundY); err != nil {
			return nil, err
		}
	}

	r := big.NewInt(0)
	for k := 0; k < dm.NumClients; k++ {
		keyNeg := new(big.Int).Neg(key.Keys[k])
		cX := internal.ModExp(cipher[k][0], keyNeg, dm.Params.NSquare)

		for i, ct := range cipher[k][1:] {
			t1 := internal.ModExp(ct, y[k][i], dm.Params.NSquare)
			cX.Mul(cX, t1)
			cX.Mod(cX, dm.Params.NSquare)
		}
		r.Add(r, cX)
		r.Mod(r, dm.Params.NSquare)
	}

	z := new(big.Int).Mul(dm.Params.N, key.Z)
	z.Sub(big.NewInt(1), z)
	z.Mod(z, dm.Params.NSquare)
	r.Add(r, z)
	r.Mod(r, dm.Params.NSquare)

	// decryption is calculated as (cX-1 mod n^2)/n
	r.Sub(r, big.NewInt(1))
	r.Mod(r, dm.Params.NSquare)
	ret := new(big.Int).Quo(r, dm.Params.N)
	// if the return value is negative this is seen as the above ret being
	// greater than n/2; in this case ret = ret - n
	nHalf := new(big.Int).Quo(dm.Params.N, big.NewInt(2))
	if ret.Cmp(nHalf) == 1 {
		ret.Sub(ret, dm.Params.N)
	}

	return ret, nil
}
