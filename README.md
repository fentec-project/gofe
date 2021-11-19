# GoFE - Functional Encryption library
[![Build Status](https://circleci.com/gh/fentec-project/gofe.svg?style=svg)](https://circleci.com/gh/fentec-project/gofe)
[![GoDoc](https://godoc.org/github.com/fentec-project/gofe?status.svg)](https://godoc.org/github.com/fentec-project/gofe)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/3ba91378a50b4446852200cc6391b4e2)](https://www.codacy.com/gh/fentec-project/gofe/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fentec-project/gofe&amp;utm_campaign=Badge_Grade)

<p align="center">
        <img src="GoFE_logo.png" width="160" />
</p>

GoFE is a cryptographic library offering different state-of-the-art
implementations of functional encryption schemes, specifically FE
schemes for _linear_ (e.g. _inner products_) and _quadratic polynomials_.

To quickly get familiar with FE, read a short and very high-level 
introduction on our [Introductory Wiki page](../../wiki/Introduction-to-FE).
A more detailed introduction with lots of interactive diagrams can be found on [this blog](https://alicebobstory.com/fe).

<!-- toc -->
- [Installing GoFE](#installing-gofe)
- [Using GoFE in your project](#using-gofe-in-your-project)
    * [Select the FE scheme](#select-the-fe-scheme)
    * [Configure selected scheme](#configure-selected-scheme)
    * [Prepare input data](#prepare-input-data)
    * [Use the scheme (examples)](#use-the-scheme-(examples))
- [Related work](#related-work)
    * [Other implementations](#other-implementations)
    * [Example projects](#example-projects)
<!-- tocstop -->

### Before using the library
Please note that the library is a work in progress and has not yet
reached a stable release. Code organization and APIs are **not stable**.
You can expect them to change at any point.

The purpose of GoFE is to support research and proof-of-concept
implementations. It **should not be used in production**.

## Installing GoFE
First, download and build the library by running either
`go install github.com/fentec-project/gofe/...` or
 `go get -u -t github.com/fentec-project/gofe/...` from the terminal (note that this also
 downloads and builds all the dependencies of the library).
 Please note that from Go version 1.18 on, `go get` will [no longer build packages](https://golang.org/doc/go-get-install-deprecation),
 and `go install` should be used instead.
 
To make sure the library works as expected, navigate to your `$GOPATH/pkg/mod/github.com/fentec-project/gofe` 
directory and run `go test -v ./...` . 
If you are still using Go version below 1.16 or have `GO111MODULE=off` set, navigate to `$GOPATH/src/github.com/fentec-project/gofe` instead.

## Using GoFE in your project
After you have successfully built the library, you can use it in your project.
Instructions below provide a brief introduction to the most important parts
of the library, and guide you through a sequence of steps that will quickly
get your FE example up and running.  

### Select the FE scheme
You can choose from the following  set of schemes:

#### Inner product schemes
You will need to import packages from `ìnnerprod` directory.

We organized implementations in two categories based on their security assumptions:

* Schemes with **selective security under chosen-plaintext 
attacks** (s-IND-CPA security):
    * Scheme by _Abdalla, Bourse, De Caro, Pointcheval_ ([paper](https://eprint.iacr.org/2015/017.pdf)). The scheme can be instantiated from DDH (`simple.DDH`), LWE (`simple.LWE`) primitives.
    * Ring-LWE scheme based on _Bermudo Mera, Karmakar, Marc, and Soleimanian_ ([paper](https://eprint.iacr.org/2021/046)), see `simple.RingLWE`.
    * Multi-input scheme based on paper by _Abdalla, Catalano, Fiore, Gay, Ursu_ ([paper](https://eprint.iacr.org/2017/972.pdf)) and instantiated from the scheme in the first point (`simple.DDHMulti`).

* Schemes with stronger **adaptive security under chosen-plaintext attacks** (IND-CPA
security) or **simulation based security** (SIM-Security for IPE):
    * Scheme based on paper by _Agrawal, Libert and Stehlé_ ([paper](https://eprint.iacr.org/2015/608.pdf)). It can be instantiated from Damgard DDH (`fullysec.Damgard` - similar to `simple.DDH`, but uses one more group element to achieve full security, similar to how Damgård's encryption scheme is obtained from ElGamal scheme ([paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_36)), LWE (`fullysec.LWE`) and Paillier (`fullysec.Paillier`) primitives.
    * Multi-input scheme based on paper by _Abdalla, Catalano, Fiore, Gay, Ursu_ ([paper](https://eprint.iacr.org/2017/972.pdf)) and instantiated from the scheme in the first point (`fullysec.DamgardMulti`).
    * Decentralized scheme based on paper by _Chotard, Dufour Sans, Gay, Phan and Pointcheval_ ([paper](https://eprint.iacr.org/2017/989.pdf)). This scheme does not require a trusted party to generate keys. It is built on pairings (`fullysec.DMCFEClient`).
    * Decentralized scheme based on paper by _Abdalla, Benhamouda, Kohlweiss, Waldner_  ([paper](https://eprint.iacr.org/2019/020.pdf)). Similarly as above this scheme this scheme does not require a trusted party to generate keys and is based on a general 
procedure for decentralization of an inner product scheme, in particular the decentralization of a Damgard DDH scheme (`fullysec.DamgardDecMultiClient`).
    * Function hiding multi-input scheme based on paper by _Datta, Okamoto, Tomida_ ([paper](https://eprint.iacr.org/2018/061.pdf)). This scheme allows clients to encrypt vectors and derive 
functional key that allows a decrytor to decrypt an inner product without revealing the ciphertext or the function (`fullysec.FHMultiIPE`).
    * Function hiding inner product scheme by _Kim, Lewi, Mandal, Montgomery, Roy, Wu_ ([paper](https://eprint.iacr.org/2016/440.pdf)). The scheme allows the decryptor to
decrypt the inner product of x and y without reveling (ciphertext) x or (function) y (`fullysec.fhipe`).
    * Partially function hiding inner product scheme by _Romain Gay_ ([paper](https://eprint.iacr.org/2020/093.pdf)). This scheme
 is a public key inner product scheme that decrypt the inner product of x and y without reveling (ciphertext) x or (function) y. This is
 achieved by limiting the space of vectors that can be encrypted with a public key (`fullysec.partFHIPE`).

#### Quadratic polynomial schemes
There are two implemented FE schemes for **quadratic multi-variate polynomials**:
* First is an efficient symmetric FE scheme by _Dufour Sans, Gay_ and _Pointcheval_ 
([paper](https://eprint.iacr.org/2018/206.pdf)) which is based on
bilinear pairings, and offers adaptive security under chosen-plaintext
attacks (IND-CPA security). You will need `SGP` scheme from package `quadratic`.
* Second is an efficient pubic key FE by _Romain Gay_ ([paper](https://eprint.iacr.org/2020/093.pdf))
that is based on the underlying partially function hiding inner product scheme and offers semi-adaptive
simulation based security. You will need `quad` scheme from package `quadratic`.

#### Schemes with the attribute based encryption (ABE)
Schemes are organized under package `abe`.

It contains four ABE schemes:
* A ciphertext policy (CP) ABE scheme named FAME by _Agrawal, Chase_ ([paper](https://eprint.iacr.org/2017/807.pdf)) allowing encrypting a
message based on a boolean expression defining a policy which attributes are needed for the decryption. It is implemented in `abe.fame`.
* A key policy (KP) ABE scheme by _Goyal, Pandey, Sahai, Waters_ ([paper](https://eprint.iacr.org/2006/309.pdf)) allowing a distribution of
keys following a boolean expression defining a policy which attributes are needed for the decryption. It is implemented in `abe.gpsw`.
* A decentralized inner product predicate scheme by _Michalevsky, Joye_ ([paper](https://eprint.iacr.org/2018/753.pdf)) allowing encryption
with policy described as a vector, and a decentralized distribution of keys based on users' vectors so that
only users with  vectors orthogonal to the encryption vector posses a key that can decrypt the ciphertext. It is implemented in `abe.dippe`.
* A multi-authority (MA) ciphertext policy (CP) ABE scheme by _Lewko, Waters_ ([paper](https://eprint.iacr.org/2010/351.pdf)) based on a boolean expression defining a policy which attributes are needed for decryption. This scheme is decentralized - the attributes can be spread across multiple different authorites. It is implemented in `abe.ma-abe`.

### Configure selected scheme
All GoFE schemes are implemented as Go structs with (at least logically)
similar APIs. So the first thing we need to do is to create a scheme instance
by instantiating the appropriate struct. For this step, we need to pass in 
some configuration, e.g. values of parameters for the selected scheme.

Let's say we selected a `simple.DDH` scheme. We create a new scheme instance with:
````go
scheme, _ := simple.NewDDH(5, 1024, big.NewInt(1000))
````

In the line above, the first argument is length of input vectors **x**
and **y**, the second argument is bit length of prime modulus _p_
(because this particular scheme operates in the &#8484;<sub>p</sub> group), and
the last argument represents the upper bound for elements of input vectors.

However, configuration parameters for different FE schemes vary quite a bit.
Please refer to [library documentation](https://godoc.org/github.com/fentec-project/gofe) regarding the meaning of parameters for
 specific schemes. For now, examples and reasonable defaults can be found in 
 the test code. 
 
After you successfully created a FE scheme instance, you can call its
 methods for:
* generation of (secret and public) master keys,
* derivation of functional encryption key,
* encryption, and
* decryption. 

### Prepare input data
#### Vectors and matrices
All GoFE chemes rely on vectors (or matrices) of big integer (`*big.Int`) 
components. 

GoFE schemes use the library's own `Vector` and `Matrix` types. They are implemented
 in the `data` package. A `Vector` is basically a wrapper around `[]*big.Int`
slice, while a `Matrix` wraps a slice of `Vector`s.

In general, you only have to worry about providing input data (usually
vectors **x** and **y**). If you already have your slice of `*big.Int`s 
defined, you can create a `Vector` by calling
`data.NewVector` function with your slice as argument, for example:
````go
// Let's say you already have your data defined in a slice of *big.Ints
x := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
xVec := data.NewVector(x)
````

Similarly, for matrices, you will first have to construct your slice of 
`Vector`s, and pass it to `data.NewMatrix` function: 
````go
vecs := make([]data.Vector, 3) // a slice of 3 vectors
// fill vecs
vecs[0] := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
vecs[1] := []*big.Int{big.NewInt(2), big.NewInt(1), big.NewInt(0)}
vecs[2] := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
xMat := data.NewMatrix(vecs)
````

#### Random data
To generate random `*big.Int` values from different probability distributions,
you can use one of our several implementations of random samplers. The samplers
are provided in the `sample` package and all implement `sample.Sampler`
 interface.
 
You can quickly construct random vectors and matrices by:
1. Configuring the sampler of your choice, for example:
    ````go
    s := sample.NewUniform(big.NewInt(100)) // will sample uniformly from [0,100)
    ````
2. Providing it as an argument to`data.NewRandomVector` or `data.NewRandomMatrix` functions. 
    ````go
    x, _ := data.NewRandomVector(5, s) // creates a random vector with 5 elements
    X, _ := data.NewRandomMatrix(2, 3, s) // creates a random 2x3 matrix
    ````
    
## Use the scheme
To see how the schemes can be used consult one of the following.

#### Tests
Every implemented scheme has an implemented test to verify the correctness
of the implementation (for example Paillier inner-product scheme implemented in
`innerprod/fullysec/paillier.go` has a corresponding test in 
`innerprod/fullysec/paillier_test.go`). One can check the appropriate test
file to see an example of how the chosen scheme can be used.

#### Examples
We give some concrete examples how to use the schemes. 
Please note that all the examples below omit error management.

##### Using a single input scheme
The example below demonstrates how to use single input scheme instances.
Although the example shows how to use the`DDH` from package 
`simple`, the usage is similar for all single input schemes, regardless
of their security properties (s-IND-CPA or IND-CPA) and instantiation
 (DDH or LWE).
 
You will see that three `DDH` structs are instantiated to simulate the
 real-world scenarios where each of the three entities involved in FE
 are on separate machines.
 
```go
// Instantiation of a trusted entity that
// will generate master keys and FE key
l := 2 // length of input vectors
bound := big.NewInt(10) // upper bound for input vector coordinates
modulusLength := 2048 // bit length of prime modulus p 
trustedEnt, _ := simple.NewDDHPrecomp(l, modulusLength, bound)
msk, mpk, _ := trustedEnt.GenerateMasterKeys()

y := data.NewVector([]*big.Int{big.NewInt(1), big.NewInt(2)})
feKey, _ := trustedEnt.DeriveKey(msk, y)

// Simulate instantiation of encryptor 
// Encryptor wants to hide x and should be given
// master public key by the trusted entity
enc := simple.NewDDHFromParams(trustedEnt.Params)
x := data.NewVector([]*big.Int{big.NewInt(3), big.NewInt(4)})
cipher, _ := enc.Encrypt(x, mpk)

// Simulate instantiation of decryptor that decrypts the cipher 
// generated by encryptor.
dec := simple.NewDDHFromParams(trustedEnt.Params)
// decrypt to obtain the result: inner prod of x and y
// we expect xy to be 11 (e.g. <[1,2],[3,4]>)
xy, _ := dec.Decrypt(cipher, feKey, y)
```

##### Using a multi input scheme
This example demonstrates how multi input FE schemes can be used.
 
 Here we assume
 that there are `numClients` encryptors (e<sub>i</sub>), each with their corresponding
 input vector x<sub>i</sub>. A trusted entity generates all the master keys needed
 for encryption and distributes appropriate keys to appropriate encryptor. Then, 
 encryptor e<sub>i</sub> uses their keys to encrypt their data x<sub>i</sub>.
 The decryptor collects ciphers from all the encryptors. It then relies on the trusted
  entity to derive a decryption key based on its own set of vectors y<sub>i</sub>. With the
  derived key, the decryptor is able to compute the result - inner product
over all vectors, as _Σ <x<sub>i</sub>,y<sub>i</sub>>._

```go
numClients := 2           // number of encryptors
l := 3                    // length of input vectors
bound := big.NewInt(1000) // upper bound for input vectors

// Simulate collection of input data.
// X and Y represent matrices of input vectors, where X are collected
// from numClients encryptors (omitted), and Y is only known by a single decryptor.
// Encryptor i only knows its own input vector X[i].
sampler := sample.NewUniform(bound)
X, _ := data.NewRandomMatrix(numClients, l, sampler)
Y, _ := data.NewRandomMatrix(numClients, l, sampler)

// Trusted entity instantiates scheme instance and generates
// master keys for all the encryptors. It also derives the FE
// key derivedKey for the decryptor.
modulusLength := 2048
multiDDH, _ := simple.NewDDHMultiPrecomp(numClients, l, modulusLength, bound)
pubKey, secKey, _ := multiDDH.GenerateMasterKeys()
derivedKey, _ := multiDDH.DeriveKey(secKey, Y)

// Different encryptors may reside on different machines.
// We simulate this with the for loop below, where numClients
// encryptors are generated.
encryptors := make([]*simple.DDHMultiClient, numClients)
for i := 0; i < numClients; i++ {
    encryptors[i] = simple.NewDDHMultiClient(multiDDH.Params)
}
// Each encryptor encrypts its own input vector X[i] with the
// keys given to it by the trusted entity.
ciphers := make([]data.Vector, numClients)
for i := 0; i < numClients; i++ {
    cipher, _ := encryptors[i].Encrypt(X[i], pubKey[i], secKey.OtpKey[i])
    ciphers[i] = cipher
}

// Ciphers are collected by decryptor, who then computes
// inner product over vectors from all encryptors.
decryptor := simple.NewDDHMultiFromParams(numClients, multiDDH.Params)
prod, _ = decryptor.Decrypt(ciphers, derivedKey, Y)
```
Note that above we instantiate multiple encryptors - in reality,
 different encryptors will be instantiated on different machines. 
 

##### Using quadratic polynomial scheme
In the example below, we omit instantiation of different entities
(encryptor and decryptor).
```go
l := 2 // length of input vectors
bound := big.NewInt(10) // Upper bound for coordinates of vectors x, y, and matrix F

// Here we fill our vectors and the matrix F (that represents the
// quadratic function) with random data from [0, bound).
sampler := sample.NewUniform(bound)
F, _ := data.NewRandomMatrix(l, l, sampler)
x, _ := data.NewRandomVector(l, sampler)
y, _ := data.NewRandomVector(l, sampler)

sgp := quadratic.NewSGP(l, bound)     // Create scheme instance
msk, _ := sgp.GenerateMasterKey()     // Create master secret key
cipher, _ := sgp.Encrypt(x, y, msk)   // Encrypt input vectors x, y with secret key
key, _ := sgp.DeriveKey(msk, F)       // Derive FE key for decryption
dec, _ := sgp.Decrypt(cipher, key, F) // Decrypt the result to obtain x^T * F * y
```

##### Using ABE schemes
Let's say we selected `abe.FAME` scheme. In the example below, we omit instantiation of different entities
(encryptor and decryptor). Say we want to encrypt the following message `msg` so that only those
who own the attributes satisfying a boolean expression 'policy' can decrypt.
```go
msg := "Attack at dawn!"
policy := "((0 AND 1) OR (2 AND 3)) AND 5"

gamma := []string{"0", "2", "3", "5"} // owned attributes

a := abe.NewFAME() // Create the scheme instance
pubKey, secKey, _ := a.GenerateMasterKeys() // Create a public key and a master secret key
msp, _ := abe.BooleanToMSP(policy, false) // The MSP structure defining the policy
cipher, _ := a.Encrypt(msg, msp, pubKey) // Encrypt msg with policy msp under public key pubKey
keys, _ := a.GenerateAttribKeys(gamma, secKey) // Generate keys for the entity with attributes gamma
dec, _ := a.Decrypt(cipher, keys, pubKey) // Decrypt the message
```

## Related work

### Other implementations

Apart from the GoFE library, there is also a C library called CiFEr that
implements many of the same schemes as GoFE, and can be found
[here](https://github.com/fentec-project/CiFEr).

### Example projects

A few reference uses of the GoFE library are provided:
* [creating a privacy preserving heatmap](https://github.com/fentec-project/FE-anonymous-heatmap),
* [evaluating a machine learning function on encrypted data](https://github.com/fentec-project/neural-network-on-encrypted-data),
* [privacy friendly data analysis on encrypted data](https://github.com/fentec-project/privacy-friendly-analyses).
