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
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// DDHMulti represents a multi input variant of the
// underlying DDH scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
type DDHMulti struct {
	// number of encryptors
	Slots int
	*DDH
}

// DDHMulti represents a multi input variant of the
// underlying DDH scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
type DDHMultiClient struct {
	*DDH
}

// NewDDHMulti configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors l, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded.
//
// It returns an error in case the underlying DDH scheme instances could
// not be properly instantiated.
func NewDDHMulti(slots, l, modulusLength int, bound *big.Int) (*DDHMulti, error) {
	ddh, err := NewDDH(l, modulusLength, bound)
	if err != nil {
		return nil, err
	}

	return &DDHMulti{
		Slots: slots,
		DDH:   ddh,
	}, nil
}

// NewDDHMultiFromParams takes the number of slots and configuration
// parameters of an existing DDH scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new DDHMulti instance.
func NewDDHMultiFromParams(slots int, params *DDHParams) *DDHMulti {
	return &DDHMulti{
		Slots: slots,
		DDH:   &DDH{params},
	}
}

// NewDDHMulti configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors l, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded.
//
// It returns an error in case the underlying DDH scheme instances could
// not be properly instantiated.
func NewDDHMultiClient(params *DDHParams) *DDHMultiClient {
	return &DDHMultiClient{
		DDH:   &DDH{params},
	}
}

// DDHMultiSecKey is a secret key for DDH multi input scheme.
type DDHMultiSecKey struct {
	Msk    data.Matrix
	OtpKey data.Matrix
}

// GenerateMasterKeys generates matrices comprised of master secret
// keys and master public keys for the scheme.
//
// It returns an error in case master keys could not be generated.
func (dm *DDHMulti) GenerateMasterKeys() (data.Matrix, *DDHMultiSecKey, error) {
	mskVecs := make([]data.Vector, dm.Slots)
	mpkVecs := make([]data.Vector, dm.Slots)
	otpVecs := make([]data.Vector, dm.Slots)

	for i := 0; i < dm.Slots; i++ {
		masterSecretKey, masterPublicKey, err := dm.DDH.GenerateMasterKeys()

		if err != nil {
			return nil, nil, fmt.Errorf("error in master key generation")
		}
		mskVecs[i] = masterSecretKey
		mpkVecs[i] = masterPublicKey

		otpVector, err := data.NewRandomVector(dm.Params.L, sample.NewUniform(dm.Params.Bound))
		if err != nil {
			return nil, nil, fmt.Errorf("error in random vector generation")
		}
		otpVecs[i] = otpVector
	}

	pubKey, err := data.NewMatrix(mpkVecs)
	if err != nil {
		return nil, nil, err
	}

	secKey, err := data.NewMatrix(mskVecs)
	if err != nil {
		return nil, nil, err
	}

	otp, err := data.NewMatrix(otpVecs)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, &DDHMultiSecKey{secKey, otp}, nil
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key and one-time pad otp (which
// is a part of the secret key). It returns the ciphertext vector.
// If encryption failed, error is returned.
func (e *DDHMultiClient) Encrypt(x data.Vector, pubKey, otp data.Vector) (data.Vector, error) {
	if err := x.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	otp = x.Add(otp)
	otpModulo := otp.Mod(e.Params.Bound)

	return e.DDH.Encrypt(otpModulo, pubKey)
}

// DDHMultiDerivedKey is functional encryption key for DDH Scheme.
type DDHMultiDerivedKey struct {
	Keys   data.Vector
	OTPKey *big.Int
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *DDHMulti) DeriveKey(secKey *DDHMultiSecKey, y data.Matrix) (*DDHMultiDerivedKey, error) {
	if err := y.CheckBound(dm.Params.Bound); err != nil {
		return nil, err
	}

	z, err := secKey.OtpKey.Dot(y)
	if err != nil {
		return nil, err
	}
	z.Mod(z, dm.Params.Bound)

	derivedKeys := make([]*big.Int, dm.Slots)

	for i := 0; i < dm.Slots; i++ {
		derivedKey, err := dm.DDH.DeriveKey(secKey.Msk[i], y[i])
		if err != nil {
			return nil, err
		}

		derivedKeys[i] = derivedKey
	}

	return &DDHMultiDerivedKey{data.NewVector(derivedKeys), z}, nil
}

// Decrypt accepts the matrix cipher comprised of encrypted vectors,
// functional encryption key, and a matrix y comprised of plaintext vectors.
// It returns the sum of inner products.
// If decryption failed, error is returned.
func (dm *DDHMulti) Decrypt(cipher[] data.Vector, key *DDHMultiDerivedKey, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(dm.Params.Bound); err != nil {
		return nil, err
	}

	sum := big.NewInt(0)
	for i := 0; i < dm.Slots; i++ {
		c, err := dm.DDH.Decrypt(cipher[i], key.Keys[i], y[i])
		if err != nil {
			return nil, err
		}

		sum.Add(sum, c)
	}

	res := new(big.Int).Sub(sum, key.OTPKey)
	res.Mod(res, dm.Params.Bound)
	return res, nil
}
