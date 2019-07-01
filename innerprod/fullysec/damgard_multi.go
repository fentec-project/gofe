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
	"github.com/fentec-project/gofe/internal/dlog"
	"github.com/fentec-project/gofe/sample"
)

// DamgardMulti represents a multi input variant of the
// underlying Damgard scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
// The participants in the scheme are clients and a central authority.
// The central authority generates keys for each client so that client i
// encrypts vector x_i. The scheme allows the central authority to
// generate a key_Y, depending on a matrix Y with rows y_i, so that
// given key_y and the ciphertext the decryptor can compute value
// Σ_i <x_i, y_i> (sum of dot products).

// DamgardMultiClient is a struct in DamgardMulti scheme, that holds
// all the shared parameters, and can represent the central authority
// or the decryptor.
type DamgardMulti struct {
	// number of clients
	NumClients int
	Bound      *big.Int
	*Damgard
}

// DamgardMultiClient represents a single client for the DamgardMulti scheme.
type DamgardMultiClient struct {
	Bound *big.Int
	*Damgard
}

// NewDamgardMulti configures a new instance of the scheme.
// It accepts the number of clients, the length of
// input vectors l, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded. It generates all the remaining
// parameters to be shared.
//
// It returns an error in case the underlying Damgard scheme
// instances could not be properly instantiated.
func NewDamgardMulti(numClients, l, modulusLength int, bound *big.Int) (*DamgardMulti, error) {
	bSquared := new(big.Int).Exp(bound, big.NewInt(2), nil)
	prod := new(big.Int).Mul(big.NewInt(int64(l*numClients*2)), bSquared)

	damgard, err := NewDamgard(l, modulusLength, bound)
	if err != nil {
		return nil, err
	}
	if prod.Cmp(damgard.Params.Q) > 0 {
		return nil, fmt.Errorf("2 * l * numClients * bound^2 should be smaller than group order")
	}
	damgard.Params.Bound = damgard.Params.Q

	return &DamgardMulti{
		NumClients: numClients,
		Bound:      bound,
		Damgard:    damgard,
	}, nil
}

// NewDamgardMultiClientFromParams takes the bound and configuration parameters of an underlying
// Damgard scheme instance, and instantiates a new DamgardMultiClient.
//
// It returns a new DamgardMultiClient instance.
func NewDamgardMultiClientFromParams(bound *big.Int, params *DamgardParams) *DamgardMultiClient {
	return &DamgardMultiClient{
		Bound:   bound,
		Damgard: &Damgard{params},
	}
}

// NewDamgardMultiFromParams takes the number of clients, bound and configuration
// parameters of an existing Damgard scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new DamgardMulti instance.
func NewDamgardMultiFromParams(numClients int, bound *big.Int, params *DamgardParams) *DamgardMulti {
	return &DamgardMulti{
		NumClients: numClients,
		Bound:      bound,
		Damgard:    &Damgard{params},
	}
}

// DamgardMultiSecKeys is a struct containing keys and one time pads for all the clients in
// the Damgard multi input scheme.
type DamgardMultiSecKeys struct {
	Msk []*DamgardSecKey
	Mpk data.Matrix
	Otp data.Matrix
}

// GenerateMasterKeys generates an the keys and one time pads for all the clients.
//
// It returns an error in case values could not be generated.
func (dm *DamgardMulti) GenerateMasterKeys() (*DamgardMultiSecKeys, error) {
	multiMsk := make([]*DamgardSecKey, dm.NumClients)
	multiMpk := make([]data.Vector, dm.NumClients)
	multiOtp := make([]data.Vector, dm.NumClients)

	for i := 0; i < dm.NumClients; i++ {
		msk, mpk, err := dm.Damgard.GenerateMasterKeys()
		if err != nil {
			return nil, fmt.Errorf("error in master key generation")
		}
		multiMsk[i] = msk
		multiMpk[i] = mpk

		otp, err := data.NewRandomVector(dm.Params.L, sample.NewUniform(dm.Params.Q))
		if err != nil {
			return nil, fmt.Errorf("error in random vector generation")
		}
		multiOtp[i] = otp
	}
	secKeys := &DamgardMultiSecKeys{
		Msk: multiMsk,
		Mpk: data.Matrix(multiMpk),
		Otp: data.Matrix(multiOtp),
	}

	return secKeys, nil
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key of the underlying Damgard scheme and
// one-time pad otp (which are a part of the secret key). It returns
// the ciphertext vector. If the encryption failed, error is returned.
func (e *DamgardMultiClient) Encrypt(x data.Vector, pubKey, otp data.Vector) (data.Vector, error) {
	if err := x.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	xAddOtp := x.Add(otp)
	xAddOtp = xAddOtp.Mod(e.Params.Q)

	return e.Damgard.Encrypt(xAddOtp, pubKey)
}

// DamgardMultiDerivedKey is a functional encryption key for DamgardMulti scheme.
type DamgardMultiDerivedKey struct {
	Keys []*DamgardDerivedKey
	Z    *big.Int // Σ <u_i, y_i> where u_i is OTP key for i-th client
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *DamgardMulti) DeriveKey(secKey *DamgardMultiSecKeys, y data.Matrix) (*DamgardMultiDerivedKey, error) {
	if err := y.CheckBound(dm.Bound); err != nil {
		return nil, err
	}

	z, err := secKey.Otp.Dot(y)
	if err != nil {
		return nil, err
	}
	z.Mod(z, dm.Params.Q)

	derivedKeys := make([]*DamgardDerivedKey, dm.NumClients)
	for i := 0; i < dm.NumClients; i++ {
		derivedKey, err := dm.Damgard.DeriveKey(secKey.Msk[i], y[i])
		if err != nil {
			return nil, err
		}
		derivedKeys[i] = derivedKey
	}

	return &DamgardMultiDerivedKey{derivedKeys, z}, nil
}

// Decrypt accepts an array of ciphers, i.e. an array of encrypted vectors,
// functional encryption key, and a matrix y describing the inner-product.
// It returns the sum of inner products Σ_i <x_i, y_i>.
// If decryption failed, error is returned.
func (dm *DamgardMulti) Decrypt(cipher []data.Vector, key *DamgardMultiDerivedKey, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(dm.Bound); err != nil {
		return nil, err
	}

	r := big.NewInt(1)
	for k := 0; k < dm.NumClients; k++ {
		num := big.NewInt(1)
		for i, ct := range cipher[k][2:] {
			t1 := internal.ModExp(ct, y[k][i], dm.Params.P)
			num = num.Mod(new(big.Int).Mul(num, t1), dm.Params.P)
		}

		t1 := new(big.Int).Exp(cipher[k][0], key.Keys[k].Key1, dm.Params.P)
		t2 := new(big.Int).Exp(cipher[k][1], key.Keys[k].Key2, dm.Params.P)

		denom := new(big.Int).Mod(new(big.Int).Mul(t1, t2), dm.Params.P)
		denomInv := new(big.Int).ModInverse(denom, dm.Params.P)
		r.Mul(r, denomInv)
		r.Mul(r, num)
		r.Mod(r, dm.Params.P)
	}

	zExp := new(big.Int).Exp(dm.Params.G, key.Z, dm.Params.P)
	zExpInv := new(big.Int).ModInverse(zExp, dm.Params.P)

	r.Mul(r, zExpInv)
	r.Mod(r, dm.Params.P)

	calc, err := dlog.NewCalc().InZp(dm.Params.P, dm.Params.Q)
	if err != nil {
		return nil, err
	}
	calc = calc.WithNeg()

	bound := new(big.Int).Mul(dm.Bound, dm.Bound)
	bound.Mul(bound, big.NewInt(int64(dm.Params.L*dm.NumClients)))
	res, err := calc.WithBound(bound).BabyStepGiantStep(r, dm.Params.G)
	return res, nil
}
