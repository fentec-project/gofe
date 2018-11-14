package abe

import (
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"github.com/cloudflare/bn256"
	"fmt"
)

type abeParams struct {
	l     int   // number of attributes
	p     *big.Int  // order of the elliptic curve
}

type Abe struct {
	Params *abeParams
}

func newAbe(l int) (*Abe){
	return &Abe{Params: &abeParams{
		l:	l,  // number of attributes in the whole universe
		p:  bn256.Order,
	}}
}

type AbePubKey struct {
	t data.VectorG2
	y *bn256.GT
}

// should we put public key into Abe struct
func (a Abe) GenerateMasterKeys() (*AbePubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.p)
	sk, err := data.NewRandomVector(a.Params.l + 1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk[:a.Params.l].MulG2()
	y := new(bn256.GT).ScalarBaseMult(sk[a.Params.l])
	return &AbePubKey{t: t, y: y,}, sk, nil
}

type AbeCipher struct {
	gamma []int
	attribToI map[int]int
	e0 *bn256.GT
	e data.VectorG2
}

func (a Abe) Encrypt(msg *bn256.GT, gamma []int, pk *AbePubKey) (*AbeCipher, error) {
	sampler := sample.NewUniform(a.Params.p)
	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}
	e0 := new(bn256.GT).Add(msg, new(bn256.GT).ScalarMult(pk.y, s))
	e := make(data.VectorG2, len(gamma))
	attribToI := make(map[int]int)
	for  i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.t[el], s)
		attribToI[el] = i
	}

	return &AbeCipher{gamma:     gamma,
					  attribToI: attribToI,
					  e0:        e0,
					  e:         e,}, nil
}


type Msp struct {
	mat data.Matrix
	rows int
	cols int
	rowToAttrib []int
}

func (a Abe) KeyGen(msp Msp, sk data.Vector) (data.VectorG1, error) {
	u, err := getSum(sk[a.Params.l], a.Params.p, msp.cols)
	if err != nil {
		return nil, err
	}
	key := make(data.VectorG1, msp.rows)
	for i := 0; i < msp.rows; i++ {
		tMapIInv := new(big.Int).ModInverse(sk[msp.rowToAttrib[i]], a.Params.p)
		matTimesU, err := msp.mat[i].Dot(u)
		if err != nil {
			return nil, err
		}
		pow := new(big.Int).Mul(tMapIInv, matTimesU)
		key[i] = new(bn256.G1).ScalarBaseMult(pow)
	}

	return key, nil
}

func getSum(y *big.Int, p *big.Int, d int) (data.Vector, error) {
	ret := make(data.Vector, d)
	sampler := sample.NewUniform(p)
	var err error
	sum := big.NewInt(0)
	for i := 0; i < d - 1; i++ {
		ret[i], err = sampler.Sample()
		if err != nil {
			return nil, err
		}
		sum.Add(sum, ret[i])
		sum.Mod(sum, p)
	}
	ret[d-1] = new(big.Int).Sub(y, sum)
	ret[d-1].Mod(ret[d-1], p)
	return ret, nil
}

type AbeKey struct {
	mat data.Matrix
	d data.VectorG1
	rowToAttrib []int
}

func (a Abe) DelagateKeys(keys data.VectorG1, msp Msp, attrib []int) (*AbeKey) {
	attribMap := make(map[int]bool)
	for _, e := range attrib {
		attribMap[e] = true
	}
	mat := make([]data.Vector, 0)
	d := make(data.VectorG1, 0)
	rowToAttrib := make([]int, 0)
	for i := 0; i < msp.rows; i++ {
		if attribMap[msp.rowToAttrib[i]] {
			mat = append(mat, msp.mat[i])
			d = append(d, keys[i])
			rowToAttrib = append(rowToAttrib, msp.rowToAttrib[i])
		}
	}

	return &AbeKey{mat:     mat,
				   d:       d,
				   rowToAttrib:  rowToAttrib,}
}


func (a Abe) Decrypt(cipher *AbeCipher, key *AbeKey, pk *AbePubKey) (*bn256.GT, error) {
	ones := make(data.Vector, len(key.mat[0]))
	for i := 0; i < len(ones); i++ {
		ones[i] = big.NewInt(1)
	}

	alpha, err := gaussianElimination(key.mat.Transpose(), ones, a.Params.p)
	if err != nil {
		return nil, err
	}

	ret := new(bn256.GT).Set(cipher.e0)
	for i := 0; i < len(ones); i++ {
		pair := bn256.Pair(key.d[i], cipher.e[cipher.attribToI[key.rowToAttrib[i]]])
		pair.ScalarMult(pair, alpha[i])
		pair.Neg(pair)
		ret.Add(ret, pair)
	}
	return ret, nil
}

func gaussianElimination(mat data.Matrix, v data.Vector, p *big.Int) (data.Vector, error) {
	cpMat := make([] data.Vector, len(mat))
	u := make(data.Vector, len(mat))
	//fmt.Println(len(mat), len(mat[0]))
	for i := 0; i < len(mat); i++ {
		cpMat[i] = make(data.Vector, len(mat[0]))
		for j := 0; j < len(mat[0]); j++ {
			cpMat[i][j] = new(big.Int).Set(mat[i][j])
		}
		u[i] = new(big.Int).Set(v[i])
	}
	m, _ := data.NewMatrix(cpMat) // error is impossible to happen
	ret := make(data.Vector, len(mat[0]))
	h, k := 0, 0
	for h < len(m) && k < len(m[0]) {
		zero := true
		for i := h; i < len(m); i++ {
			if m[i][k].Sign() != 0 {
				//fmt.Println(h, i)
				//fmt.Println(m)
				m[h], m[i] = m[i], m[h]

				u[h], u[i] = u[i], u[h]
				zero = false
				break
			}
		}
		if zero {
			if u[k].Sign() != 0 {
				return nil, fmt.Errorf("no solution")
			} else {
				ret[k] = big.NewInt(0)
			}
			k++
			continue
		}
		mHKInv := new(big.Int).ModInverse(m[h][k], p)
		//fmt.Println(mHKInv, "inv")
		for i := h + 1; i < len(m); i++ {
			f := new(big.Int).Mul(mHKInv, m[i][k])
			//fmt.Println(f, "f")
			m[i][k] = big.NewInt(0)
			for j := k + 1; j < len(m[0]); j++ {
				//fmt.Println(m[i][j], m[h][j], new(big.Int).Mul(f, m[h][j]))
				m[i][j].Sub(m[i][j], new(big.Int).Mul(f, m[h][j]))
				//fmt.Println(m[i][j])
				m[i][j].Mod(m[i][j], p)
			}
			u[i].Sub(u[i], new(big.Int).Mul(f, u[h]))
			u[i].Mod(u[i], p)
		}
		//fmt.Println(m)
		k++
		h++
	}
	for i := h; i < len(m); i++ {
		if u[i].Sign() != 0 {
			return nil, fmt.Errorf("no solution")
		}
	}
	for j := k; j < len(m[0]); j++ {
		ret[j] = big.NewInt(0)
	}

	//fmt.Println(m, u)
	//fmt.Println(h, k)
	//fmt.Println(ret)
	for h > 0 {
		h--
		for k > 0 {
			k--
			//fmt.Println(ret[k])
			if ret[k] == nil {
				//fmt.Println(ret[k], 2)
				//fmt.Println(len(m[h][k+1:]), len(ret[k+1:]))
				tmpSum, _ := m[h][k+1:].Dot(ret[k+1:])
				ret[k] = new(big.Int).Sub(u[h], tmpSum)
				mHKInv := new(big.Int).ModInverse(m[h][k], p)
				ret[k].Mul(ret[k], mHKInv)
				ret[k].Mod(ret[k], p)
				break
			}
		}
	}
	//fmt.Println(ret)

	return ret, nil
}