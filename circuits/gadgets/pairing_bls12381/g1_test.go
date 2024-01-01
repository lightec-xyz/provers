package pairing_bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"runtime/debug"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

type G1ConversionCircuit struct {
	G1AffineVar  G1Affine
	PublicKeyVar [LenOfPubkey]frontend.Variable
}

func (c *G1ConversionCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[BLS12381Fp, BLS12381Fr](api, sw_emulated.GetCurveParams[BLS12381Fp]())
	if err != nil {
		return err
	}

	g1Affine, err := NewG1AffineFromBytes(api, c.PublicKeyVar)
	if err != nil {
		return err
	}

	curve.AssertIsEqual(&g1Affine, &c.G1AffineVar)
	return nil
}

func TestCompressedPublicKeyBytesToG1Affine_Emulated(t *testing.T) {
	bs, err := hex.DecodeString("814453665c4b46dad568d69d0a3d211c70829ce7c5c17549713ed0996c8743e6b55b3797ea19c0eebac07b0e163fae9a")
	assert.NoError(t, err)

	var g1Affine bls12381.G1Affine
	_, err = g1Affine.SetBytes(bs)
	assert.NoError(t, err)

	publicKey := g1Affine.Bytes()
	fmt.Printf("compressedPublicKey: %v\n", hex.EncodeToString(publicKey[:]))
	//x := g1Affine.X.Bytes()
	//y := g1Affine.Y.Bytes()
	//fmt.Printf("x: %v\n", hex.EncodeToString(x[:]))
	//fmt.Printf("y: %v\n", hex.EncodeToString(y[:]))

	var tmp1, tmp2 bls12381fp.Element
	ySquare := tmp1.Square(&g1Affine.Y)
	xSquare := tmp2.Square(&g1Affine.X)
	xCubic := tmp2.Mul(xSquare, &g1Affine.X)
	b := bls12381fp.NewElement(4)
	xSum := xCubic.Add(xCubic, &b)
	check := xSum.Equal(ySquare)
	assert.True(t, check)

	var publicKeyVar [LenOfPubkey]frontend.Variable
	for i := 0; i < len(publicKeyVar); i++ {
		publicKeyVar[i] = frontend.Variable(publicKey[i])
	}

	g1AffineVar := NewG1Affine(g1Affine)

	circuit := G1ConversionCircuit{
		G1AffineVar:  g1AffineVar,
		PublicKeyVar: publicKeyVar,
	}

	err = test.IsSolved(&G1ConversionCircuit{}, &circuit, ecc.BN254.ScalarField())
	assert.NoError(t, err)
}

func TestCompressedPublicKeyBytesToG1Affine_Groth16(t *testing.T) {
	bs, err := hex.DecodeString("814453665c4b46dad568d69d0a3d211c70829ce7c5c17549713ed0996c8743e6b55b3797ea19c0eebac07b0e163fae9a")
	assert.NoError(t, err)

	var g1Affine bls12381.G1Affine
	_, err = g1Affine.SetBytes(bs)
	assert.NoError(t, err)

	publicKey := g1Affine.Bytes()
	fmt.Printf("compressedPublicKey: %v\n", hex.EncodeToString(publicKey[:]))

	var publicKeyVar [LenOfPubkey]frontend.Variable
	for i := 0; i < len(publicKeyVar); i++ {
		publicKeyVar[i] = frontend.Variable(publicKey[i])
	}

	g1AffineVar := NewG1Affine(g1Affine)

	circuit := G1ConversionCircuit{
		G1AffineVar:  g1AffineVar,
		PublicKeyVar: publicKeyVar,
	}

	compileStart := time.Now()
	fmt.Printf("compile start...\n")
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &G1ConversionCircuit{})
	if err != nil {
		log.Fatal("frontend.Compile")
	}
	compileDuration := time.Since(compileStart)
	fmt.Printf("compile duration:%v\n", compileDuration)

	// groth16 zkSNARK: Setup
	fmt.Printf("setup start...\n")
	setupStart := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatal("groth16.Setup")
	}
	setUpDuration := time.Since(setupStart)
	fmt.Printf("setup duration:%v\n", setUpDuration)

	witness, _ := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	fmt.Printf("proof generate start...\n")
	proofGenStart := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}
	proofGenDuration := time.Since(proofGenStart)
	fmt.Printf("proof generation time: %v\n", proofGenDuration)

	fmt.Printf("proof verify start...\n")
	proofVerifyStart := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}
	proofVerifyDuration := time.Since(proofVerifyStart)
	fmt.Printf("proof verification time: %v\n", proofVerifyDuration)

	numConstraints := cs.GetNbConstraints()
	numWitness := cs.GetNbSecretVariables()
	numInstance := cs.GetNbPublicVariables()
	fmt.Printf("numConstraints:%v, numWitness:%v, numInstance:%v\n", numConstraints, numWitness, numInstance)
}

func TestCompressedPublicKeyBytesToG1Affine_Emulated_Random(t *testing.T) {
	//t.Skip("skip")
	var fr BLS12381Fr
	for i := 0; i < 100000; i++ {
		fmt.Printf("iter:%v\n", i)
		sk, err := rand.Int(rand.Reader, fr.Modulus())
		var g1Affine bls12381.G1Affine
		g1Affine.ScalarMultiplicationBase(sk)

		publicKey := g1Affine.Bytes()
		fmt.Printf("compressedPublicKey: %v\n", hex.EncodeToString(publicKey[:]))

		var publicKeyVar [LenOfPubkey]frontend.Variable
		for i := 0; i < len(publicKeyVar); i++ {
			publicKeyVar[i] = frontend.Variable(publicKey[i])
		}

		g1AffineVar := NewG1Affine(g1Affine)
		circuit := G1ConversionCircuit{
			G1AffineVar:  g1AffineVar,
			PublicKeyVar: publicKeyVar,
		}

		err = test.IsSolved(&G1ConversionCircuit{}, &circuit, ecc.BLS12_381.ScalarField())
		assert.NoError(t, err)
	}
}

func TestCompressedPublicKeyBytesToG1Affine_Groth16_Random(t *testing.T) {
	//t.Skip("skip")
	var fr BLS12381Fr
	for i := 0; i < 10000; i++ {
		fmt.Printf("iter:%v\n", i)
		sk, err := rand.Int(rand.Reader, fr.Modulus())
		var g1Affine bls12381.G1Affine
		g1Affine.ScalarMultiplicationBase(sk)

		publicKey := g1Affine.Bytes()
		fmt.Printf("compressedPublicKey: %v\n", hex.EncodeToString(publicKey[:]))

		var publicKeyVar [LenOfPubkey]frontend.Variable
		for i := 0; i < len(publicKeyVar); i++ {
			publicKeyVar[i] = frontend.Variable(publicKey[i])
		}

		g1AffineVar := NewG1Affine(g1Affine)
		circuit := G1ConversionCircuit{
			G1AffineVar:  g1AffineVar,
			PublicKeyVar: publicKeyVar,
		}

		cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &G1ConversionCircuit{})
		if err != nil {
			log.Fatal("frontend.Compile")
		}

		// groth16 zkSNARK: Setup
		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			log.Fatal("groth16.Setup")
		}

		witness, _ := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
		publicWitness, _ := witness.Public()

		// groth16: Prove & Verify
		proof, err := groth16.Prove(cs, pk, witness)
		if err != nil {
			debug.PrintStack()
			log.Fatal("prove computation failed...", err)
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Fatal("groth16 verify failed...")
		}
	}
}
