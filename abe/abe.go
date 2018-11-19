package abe

import (
	"fmt"
	"math/big"

	"strconv"
	"strings"

	"github.com/cloudflare/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

type abeParams struct {
	l int      // number of attributes
	p *big.Int // order of the elliptic curve
}

type Abe struct {
	Params *abeParams
}

func newAbe(l int) *Abe {
	return &Abe{Params: &abeParams{
		l: l, // number of attributes in the whole universe
		p: bn256.Order,
	}}
}

type AbePubKey struct {
	t data.VectorG2
	y *bn256.GT
}

// should we put public key into Abe struct
func (a Abe) GenerateMasterKeys() (*AbePubKey, data.Vector, error) {
	sampler := sample.NewUniform(a.Params.p)
	sk, err := data.NewRandomVector(a.Params.l+1, sampler)
	if err != nil {
		return nil, nil, err
	}
	t := sk[:a.Params.l].MulG2()
	y := new(bn256.GT).ScalarBaseMult(sk[a.Params.l])

	return &AbePubKey{t: t, y: y}, sk, nil
}

type AbeCipher struct {
	gamma     []int
	attribToI map[int]int
	e0        *bn256.GT
	e         data.VectorG2
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
	for i, el := range gamma {
		e[i] = new(bn256.G2).ScalarMult(pk.t[el], s)
		attribToI[el] = i
	}

	return &AbeCipher{gamma: gamma,
		attribToI: attribToI,
		e0:        e0,
		e:         e}, nil
}

type Msp struct {
	mat         data.Matrix
	rowToAttrib []int
}

func (a Abe) KeyGen(msp *Msp, sk data.Vector) (data.VectorG1, error) {
	if len(msp.mat) == 0 || len(msp.mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	u, err := getSum(sk[a.Params.l], a.Params.p, len(msp.mat[0]))
	if err != nil {
		return nil, err
	}

	key := make(data.VectorG1, len(msp.mat))
	for i := 0; i < len(msp.mat); i++ {
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
	for i := 0; i < d-1; i++ {
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
	mat         data.Matrix
	d           data.VectorG1
	rowToAttrib []int
}

func (a Abe) DelagateKeys(keys data.VectorG1, msp *Msp, attrib []int) *AbeKey {
	attribMap := make(map[int]bool)
	for _, e := range attrib {
		attribMap[e] = true
	}

	mat := make([]data.Vector, 0)
	d := make(data.VectorG1, 0)
	rowToAttrib := make([]int, 0)
	for i := 0; i < len(msp.mat); i++ {
		if attribMap[msp.rowToAttrib[i]] {
			mat = append(mat, msp.mat[i])
			d = append(d, keys[i])
			rowToAttrib = append(rowToAttrib, msp.rowToAttrib[i])
		}
	}

	return &AbeKey{mat: mat,
		d:           d,
		rowToAttrib: rowToAttrib}
}

func (a Abe) Decrypt(cipher *AbeCipher, key *AbeKey) (*bn256.GT, error) {
	ones := make(data.Vector, len(key.mat[0]))
	for i := 0; i < len(ones); i++ {
		ones[i] = big.NewInt(1)
	}

	alpha, err := gaussianElimination(key.mat.Transpose(), ones, a.Params.p)
	ww, _ := key.mat.Transpose().MulVec(alpha)
	ww = ww.Mod(a.Params.p)
	fmt.Println("here2", ww)
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

// BooleanToMsp takes as an input a boolean expression (without a NOT gate) and
// outputs a msp structure representing the expression, i.e. a matrix whose rows
// correspond to attributes used in the expression and with the property that a
// boolean expression assigning 1 to some attributes is satisfied iff the
// corresponding rows span a vector [1, 1,..., 1] in Z_p, and a vector whose i-th entry
// indicates to which attribute the i-th row corresponds.
func BooleanToMsp(boolExp string, p *big.Int) (*Msp, error) {
	vec := make(data.Vector, 1)
	vec[0] = big.NewInt(1)
	msp, _, err := booleanToMspIterative(boolExp, vec, 1)
	if err != nil {
		return nil, err
	}

	// create an invertible matrix that maps [1, 0,..., 0] to [1,1,...,1]
	perm := make(data.Matrix, len(msp.mat[0]))
	fmt.Println(msp.mat)
	for i:=0; i < len(msp.mat[0]); i++ {
		perm[i] = make(data.Vector, len(msp.mat[0]))
		for j:=0; j < len(msp.mat[0]); j++ {
			if i == 0 || j == i {
				perm[i][j] = big.NewInt(1)
			} else {
				perm[i][j] = big.NewInt(0)
			}

		}
	}
	fmt.Println(perm)
	msp.mat, err = msp.mat.Mul(perm)
	msp.mat = msp.mat.Mod(p)
	return msp, err
}

// booleanToMspIterative iteratively builds a msp structure by splitting the expression
// into two parts separated by an AND or OR gate, generating a msp structure on each of
// them, and joining both structures together. The structure is such the boolean expression
// assigning 1 to some attributes is satisfied iff the corresponding rows span a vector
// [1, 0,..., 0]. The algorithm is known as Lewko-Waters algorithm, see Appendix G in
// https://eprint.iacr.org/2010/351.pdf.
func booleanToMspIterative(boolExp string, vec data.Vector, c int) (*Msp, int, error) {
	boolExp = strings.TrimSpace(boolExp)
	numBrc := 0
	var boolExp1 string
	var boolExp2 string
	var c1 int
	var cOut int
	var msp1 *Msp
	var msp2 *Msp
	var err error
	found := false

	// find the main AND or OR gate
	for i, e := range boolExp {
		if e == '(' {
			numBrc++
			continue
		}
		if e == ')' {
			numBrc--
			continue
		}
		if numBrc == 0 && i < len(boolExp)-3 && boolExp[i:i+3] == "AND" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+3:]
			vec1, vec2 := makeAndVecs(vec, c)
			msp1, c1, err = booleanToMspIterative(boolExp1, vec1, c+1)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMspIterative(boolExp2, vec2, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
		if numBrc == 0 && i < len(boolExp)-2 && boolExp[i:i+2] == "OR" {
			boolExp1 = boolExp[:i]
			boolExp2 = boolExp[i+2:]
			msp1, c1, err = booleanToMspIterative(boolExp1, vec, c)
			if err != nil {
				return nil, 0, err
			}
			msp2, cOut, err = booleanToMspIterative(boolExp2, vec, c1)
			if err != nil {
				return nil, 0, err
			}
			found = true
			break
		}
	}

	// If the AND or OR gate is not found then there are two options,
	// ether the whole expression is in brackets, or the the expression
	// is only one attribute. It nether of both is is true, then
	// an error is returned while converting the expression into an
	// attribute
	if found == false {
		if boolExp[0] == '(' && boolExp[len(boolExp)-1] == ')' {
			boolExp = boolExp[1:(len(boolExp) - 1)]
			return booleanToMspIterative(boolExp, vec, c)
		}

		attrib, err := strconv.Atoi(boolExp)
		if err != nil {
			return nil, 0, err
		}
		mat := make(data.Matrix, 1)
		mat[0] = make(data.Vector, c)
		for i := 0; i < c; i++ {
			mat[0][i] = new(big.Int).Set(vec[i])
		}
		rowToAttrib := make([]int, 1)
		rowToAttrib[0] = attrib
		return &Msp{mat: mat, rowToAttrib: rowToAttrib}, c, nil
	} else {
		// otherwise we join the two msp structures into one
		mat := make(data.Matrix, len(msp1.mat)+len(msp2.mat))
		for i := 0; i < len(msp1.mat); i++ {
			mat[i] = make(data.Vector, cOut)
			for j := 0; j < len(msp1.mat[0]); j++ {
				mat[i][j] = msp1.mat[i][j]
			}
			for j := len(msp1.mat[0]); j < cOut; j++ {
				mat[i][j] = big.NewInt(0)
			}
		}
		for i := 0; i < len(msp2.mat); i++ {
			mat[i+len(msp1.mat)] = msp2.mat[i]
		}
		rowToAttrib := append(msp1.rowToAttrib, msp2.rowToAttrib...)

		return &Msp{mat: mat, rowToAttrib: rowToAttrib}, cOut, nil
	}
}

// makeAndVecs is a helping structure that given a vector and and counter
// creates two new vectors used whenever an AND gate is found in a iterative
// step of BooleanToMsp
func makeAndVecs(vec data.Vector, c int) (data.Vector, data.Vector) {
	vec1 := make(data.Vector, c+1)
	vec2 := make(data.Vector, c+1)
	for i := 0; i < c; i++ {
		vec1[i] = big.NewInt(0)
		if i < len(vec) {
			vec2[i] = new(big.Int).Set(vec[i])
		} else {
			vec2[i] = big.NewInt(0)
		}
	}
	vec1[c] = big.NewInt(-1)
	vec2[c] = big.NewInt(1)

	return vec1, vec2
}

// gaussianElimination solves a vector equation mat * x = v and finds vector x,
// using Gaussian elimination. Arithmetic operations are considered to be over
// Z_p, where p should be a prime number. If such x does not exist, then the
// function returns an error.
func gaussianElimination(mat data.Matrix, v data.Vector, p *big.Int) (data.Vector, error) {
	fmt.Println(mat, v, p)
	if len(mat) == 0 || len(mat[0]) == 0 {
		return nil, fmt.Errorf("the matrix should not be empty")
	}
	if len(mat) != len(v) {
		return nil, fmt.Errorf("dimensions should match")
	}

	// we copy matrix mat into m and v into u
	cpMat := make([]data.Vector, len(mat))
	u := make(data.Vector, len(mat))
	for i := 0; i < len(mat); i++ {
		cpMat[i] = make(data.Vector, len(mat[0]))
		for j := 0; j < len(mat[0]); j++ {
			cpMat[i][j] = new(big.Int).Set(mat[i][j])
		}
		u[i] = new(big.Int).Set(v[i])
	}
	m, _ := data.NewMatrix(cpMat) // error is impossible to happen

	// m and u are transformed to be in upper triangular form
	ret := make(data.Vector, len(mat[0]))
	h, k := 0, 0
	for h < len(m) && k < len(m[0]) {
		zero := true
		for i := h; i < len(m); i++ {
			if m[i][k].Sign() != 0 {
				m[h], m[i] = m[i], m[h]

				u[h], u[i] = u[i], u[h]
				zero = false
				break
			}
		}
		if zero {
			ret[k] = big.NewInt(0)
			k++
			continue
		}
		mHKInv := new(big.Int).ModInverse(m[h][k], p)
		for i := h + 1; i < len(m); i++ {
			f := new(big.Int).Mul(mHKInv, m[i][k])
			m[i][k] = big.NewInt(0)
			for j := k + 1; j < len(m[0]); j++ {
				m[i][j].Sub(m[i][j], new(big.Int).Mul(f, m[h][j]))
				m[i][j].Mod(m[i][j], p)
			}
			u[i].Sub(u[i], new(big.Int).Mul(f, u[h]))
			u[i].Mod(u[i], p)
		}
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

	// use the upper triangular form to obtain the solution
	for h > 0 {
		h--
		for k > 0 {
			k--
			if ret[k] == nil {
				tmpSum, _ := m[h][k+1:].Dot(ret[k+1:])
				ret[k] = new(big.Int).Sub(u[h], tmpSum)
				mHKInv := new(big.Int).ModInverse(m[h][k], p)
				ret[k].Mul(ret[k], mHKInv)
				ret[k].Mod(ret[k], p)
				break
			}
		}
	}

	return ret, nil
}
