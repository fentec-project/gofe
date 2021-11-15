/*
 * Copyright (c) 2021 XLAB d.o.o
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

/* TODO:
 * - add AES-CBC
 */

package abe

import (
    "crypto/aes"
    cbc "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "math/big"
    "io"
    "github.com/fentec-project/bn256"
    "github.com/fentec-project/gofe/data"
    "github.com/fentec-project/gofe/sample"
)

type MAABE struct {
    P *big.Int
    g1 *bn256.G1
    g2 *bn256.G2
}

func NewMAABE() *MAABE {
    return &MAABE{
            P: bn256.Order,
            g1: new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
            g2: new(bn256.G2).ScalarBaseMult(big.NewInt(1)),
    }
}

type MAABEPubKey struct {
    Attribs []string
    EggToAlpha map[string]*bn256.GT
    GToY map[string]*bn256.G2
}

type MAABESecKey struct {
    Attribs []string
    Alpha map[string]*big.Int
    Y map[string]*big.Int
}

type MAABEAuth struct {
    Id string
    Pk *MAABEPubKey
    Sk *MAABESecKey
}

func (a *MAABE) NewMAABEAuth(id string, attribs []string) (*MAABEAuth, error) {
    numattrib := len(attribs)
    // sanity checks
    if numattrib == 0 {
        return nil, fmt.Errorf("empty set of authority attributes")
    }
    if len(id) == 0 {
        return nil, fmt.Errorf("empty id string")
    }
    // rand generator
    sampler := sample.NewUniform(a.P)
    // generate seckey
    alpha_i, err := data.NewRandomVector(numattrib, sampler)
    if err != nil {
        return nil, err
    }
    y_i, err := data.NewRandomVector(numattrib, sampler)
    if err != nil {
        return nil, err
    }
    alpha := make(map[string]*big.Int)
    y := make(map[string]*big.Int)
    for i, at := range attribs {
        alpha[at] = alpha_i[i]
        y[at] = y_i[i]
    }
    // alpha := data.NewConstantVector(numattrib, big.NewInt(0))//TEST
    // y := data.NewConstantVector(numattrib, big.NewInt(0))//TEST
    // generate pubkey
    eggToAlpha := make(map[string]*bn256.GT)
    gToY := make(map[string]*bn256.G2)
    for _, at := range attribs {
        eggToAlpha[at] = new(bn256.GT).ScalarMult(bn256.Pair(a.g1, a.g2), alpha[at])
        gToY[at] = new(bn256.G2).ScalarMult(a.g2, y[at])
    }
    sk := &MAABESecKey{Attribs: attribs, Alpha: alpha, Y: y}
    pk := &MAABEPubKey{Attribs: attribs, EggToAlpha: eggToAlpha, GToY: gToY}
    return &MAABEAuth{
        Id: id,
        Pk: pk,
        Sk: sk,
    }, nil
}

type MAABECipher struct {
    C0 *bn256.GT
    C1x map[string]*bn256.GT
    C2x map[string]*bn256.G2
    C3x map[string]*bn256.G2
    Msp *MSP
    SymEnc []byte // symmetric encryption of the string message
    Iv []byte // initialization vector for symmetric encryption
}

func (a *MAABE) Encrypt(msg string, msp *MSP, pks []*MAABEPubKey) (*MAABECipher, error) {
    // sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
    mspRows := msp.Mat.Rows()
    mspCols := msp.Mat.Cols()
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}
    if len(msg) == 0 {
        return nil, fmt.Errorf("message cannot be empty")
    }
    // msg is encrypted with AES-CBC with a random key that is encrypted with
    // MA-ABE
    // generate secret key
    _, symKey, err := bn256.RandomGT(rand.Reader)
    if err != nil {
        return nil, err
    }
    // generate new AES-CBC params
    keyCBC := sha256.Sum256([]byte(symKey.String()))
    cipherAES, err := aes.NewCipher(keyCBC[:])
    if err != nil {
        return nil, err
    }
    iv := make([]byte, cipherAES.BlockSize())
    _, err = io.ReadFull(rand.Reader, iv)
    if err != nil {
        return nil, err
    }
    encrypterCBC := cbc.NewCBCEncrypter(cipherAES, iv)
    // interprete msg as a byte array and pad it according to PKCS7 standard
    msgByte := []byte(msg)
    padLen := cipherAES.BlockSize() - (len(msgByte) % cipherAES.BlockSize())
    msgPad := make([]byte, len(msgByte) + padLen)
    copy(msgPad, msgByte)
    for i := len(msgByte); i < len(msgPad); i++ {
        msgPad[i] = byte(padLen)
    }
    // encrypt data
    symEnc := make([]byte, len(msgPad))
    encrypterCBC.CryptBlocks(symEnc, msgPad)

    // now encrypt symKey with MA-ABE
    // msg := bn256.GetGTOne()//TEST
    // rand generator
    sampler := sample.NewUniform(a.P)
    // pick random vector v with random s as first element
    v, err := data.NewRandomVector(mspCols, sampler)
    if err != nil {
        return nil, err
    }
    // v := data.NewConstantVector(mspCols, big.NewInt(0))//TEST
    s := v[0]
    // s_tmp, err := data.NewRandomVector(1, sampler)
    if err != nil {
        return nil, err
    }
    // s := s_tmp[0]
    // v[0] = s
    lambda_i, err := msp.Mat.MulVec(v)
    if err != nil {
        return nil, err
    }
    if len(lambda_i) != mspRows {
        return nil, fmt.Errorf("wrong lambda len")
    }
    lambda := make(map[string]*big.Int)
    for i, at := range msp.RowToAttrib {
        lambda[at] = lambda_i[i]
    }
    // pick random vector w with 0 as first element
    w, err := data.NewRandomVector(mspCols, sampler)
    if err != nil {
        return nil, err
    }
    // w := data.NewConstantVector(mspCols, big.NewInt(1))//TEST
    w[0] = big.NewInt(0)
    omega_i, err := msp.Mat.MulVec(w)
    if err != nil {
        return nil, err
    }
    if len(omega_i) != mspRows {
        return nil, fmt.Errorf("wrong omega len")
    }
    omega := make(map[string]*big.Int)
    for i, at := range msp.RowToAttrib {
        omega[at] = omega_i[i]
    }
    // calculate ciphertext
    c0 := new(bn256.GT).Add(symKey, new(bn256.GT).ScalarMult(bn256.Pair(a.g1, a.g2), s))
    c1 := make(map[string]*bn256.GT)
    c2 := make(map[string]*bn256.G2)
    c3 := make(map[string]*bn256.G2)
    // get randomness
    r_i, err := data.NewRandomVector(mspRows, sampler)
    // r := data.NewConstantVector(mspRows, big.NewInt(0))//TEST
    r := make(map[string]*big.Int)
    for i, at := range msp.RowToAttrib {
        r[at] = r_i[i]
    }
    if err != nil {
        return nil, err
    }
    for _, at := range msp.RowToAttrib {
        // find the correct pubkey
        foundPK := false
        for _, pk := range pks {
            if pk.EggToAlpha[at] != nil {
                signLambda := lambda[at].Cmp(big.NewInt(0))
                signOmega := omega[at].Cmp(big.NewInt(0))
                var tmpLambda *bn256.GT
                var tmpOmega *bn256.G2
                if signLambda >= 0 {
                    tmpLambda = new(bn256.GT).ScalarMult(bn256.Pair(a.g1, a.g2), lambda[at])
                } else {
                    tmpLambda = new(bn256.GT).ScalarMult(new(bn256.GT).Neg(bn256.Pair(a.g1, a.g2)), new(big.Int).Abs(lambda[at]))
                }
                if signOmega >= 0 {
                    tmpOmega = new(bn256.G2).ScalarMult(a.g2, omega[at])
                } else {
                    tmpOmega = new(bn256.G2).ScalarMult(new(bn256.G2).Neg(a.g2), new(big.Int).Abs(omega[at]))
                }
                c1[at] = new(bn256.GT).Add(tmpLambda, new(bn256.GT).ScalarMult(pk.EggToAlpha[at], r[at]))
                c2[at] = new(bn256.G2).ScalarMult(a.g2, r[at])
                c3[at] = new(bn256.G2).Add(new(bn256.G2).ScalarMult(pk.GToY[at], r[at]), tmpOmega)
                foundPK = true
                break
            }
        }
        if foundPK == false {
            return nil, fmt.Errorf("attribute not found in any pubkey")
        }
    }
    return &MAABECipher{
        C0: c0,
        C1x: c1,
        C2x: c2,
        C3x: c3,
        Msp: msp,
        SymEnc: symEnc,
        Iv: iv,
    }, nil
}

type MAABEKey struct {
    Gid string
    Attrib string
    Key *bn256.G1
}

func (a *MAABE) GenerateAttribKey(gid string, attrib string, sk *MAABESecKey) (*MAABEKey, error) {
    // sanity checks
    if len(gid) == 0 {
        return nil, fmt.Errorf("GID cannot be empty")
    }
    if len(attrib) == 0 {
        return nil, fmt.Errorf("attribute cannot be empty")
    }
    hash, err := bn256.HashG1(gid)
    if err != nil {
        return nil, err
    }
    var k *bn256.G1
    if sk.Alpha[attrib] != nil {
        k = new(bn256.G1).Add(new(bn256.G1).ScalarMult(a.g1, sk.Alpha[attrib]), new(bn256.G1).ScalarMult(hash, sk.Y[attrib]))
    } else {
        return nil, fmt.Errorf("attribute not found in secret key")
    }
    return &MAABEKey{
        Gid: gid,
        Attrib: attrib,
        Key: k,
    }, nil
}

func (a * MAABE) Decrypt(ct *MAABECipher, ks []*MAABEKey) (string, error) {
    // sanity checks
    if len(ks) == 0 {
        return "", fmt.Errorf("empty set of attribute keys")
    }
    gid := ks[0].Gid
    for _, k := range ks {
        if k.Gid != gid {
            return "", fmt.Errorf("not all GIDs are the same")
        }
    }
    // get hashed GID
    hash, err := bn256.HashG1(gid)
    if err != nil {
        return "", err
    }
    // find out which attributes are valid and extract them
    goodMatRows := make([]data.Vector, 0)
    goodAttribs := make([]string, 0)
    aToK := make(map[string]*MAABEKey)
    for _, k := range ks {
        aToK[k.Attrib] = k
    }
    for i, at := range ct.Msp.RowToAttrib {
        if aToK[at] != nil {
            goodMatRows = append(goodMatRows, ct.Msp.Mat[i])
            goodAttribs = append(goodAttribs, at)
        }
    }
    goodMat, err := data.NewMatrix(goodMatRows)
    if err != nil {
        return "", err
    }
    //choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
    // if they don't exist, keys are not ok
    goodCols := goodMat.Cols()
    one := data.NewConstantVector(goodCols, big.NewInt(0))
    one[0] = big.NewInt(1)
    c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
    if err != nil {
        return "", err
    }
    cx := make(map[string]*big.Int)
    for i, at := range goodAttribs {
        cx[at] = c[i]
    }
    // compute intermediate values
    eggLambda := make(map[string]*bn256.GT)
    for _, at := range goodAttribs {
        if ct.C1x[at] != nil && ct.C2x[at] != nil && ct.C3x[at] != nil {
            num := new(bn256.GT).Add(ct.C1x[at], bn256.Pair(hash, ct.C3x[at]))
            den := new(bn256.GT).Neg(bn256.Pair(aToK[at].Key, ct.C2x[at]))
            eggLambda[at] = new(bn256.GT).Add(num, den)
        } else {
            return "", fmt.Errorf("attribute %s not in ciphertext dicts", at)
        }
    }
    eggs := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
    // eggs := bn256.GetGTOne()//TEST
    for _, at := range goodAttribs {
        if eggLambda[at] != nil {
            sign := cx[at].Cmp(big.NewInt(0))
            if sign == 1 {
                eggs.Add(eggs, new(bn256.GT).ScalarMult(eggLambda[at], cx[at]))
            } else if sign == -1 {
                eggs.Add(eggs, new(bn256.GT).ScalarMult(new(bn256.GT).Neg(eggLambda[at]), new(big.Int).Abs(cx[at])))
            }
        } else {
            return "", fmt.Errorf("missing intermediate result")
        }
    }
    // calculate key for symmetric encryption
    symKey := new(bn256.GT).Add(ct.C0, new(bn256.GT).Neg(eggs))
    // now decrypt message with it
	keyCBC := sha256.Sum256([]byte(symKey.String()))
	cipherAES, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return "", err
	}
	msgPad := make([]byte, len(ct.SymEnc))
	decrypter := cbc.NewCBCDecrypter(cipherAES, ct.Iv)
	decrypter.CryptBlocks(msgPad, ct.SymEnc)
	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return "", fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]
	return string(msgByte), nil
}
