package pairing_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

const LenOfPubkey = 48

type G1Affine = sw_emulated.AffinePoint[BLS12381Fp]

func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BLS12381Fp](v.X),
		Y: emulated.ValueOf[BLS12381Fp](v.Y),
	}
}

// NewG1AffineFromBytes rebuild the G1Affine from compressed public key
func NewG1AffineFromBytes(api frontend.API, v [LenOfPubkey]frontend.Variable) (G1Affine, error) {
	//mCompressedSmallest   byte = 0b100 << 5
	//mCompressedLargest    byte = 0b101 << 5
	//PublicKeyVar[0] is big-endian,bitsVar is little-endian, check the msb
	msbVar := bits.ToBinary(api, v[0], bits.WithNbDigits(8))

	//bitsVar is little-endian, the 3 msb are bits[7:5]
	api.AssertIsEqual(msbVar[7], 1)
	api.AssertIsEqual(msbVar[6], 0)
	isLargest := msbVar[5]

	//clear bits[7~5]
	msbVar[7] = api.Xor(msbVar[7], msbVar[7])
	msbVar[6] = api.Xor(msbVar[6], msbVar[6])
	msbVar[5] = api.Xor(msbVar[5], msbVar[5])

	var byteX [LenOfPubkey]frontend.Variable
	byteX[0] = bits.FromBinary(api, msbVar[:], bits.WithNbDigits(8))
	for i := 1; i < LenOfPubkey; i++ {
		byteX[i] = v[i]
	}

	fpField, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		return G1Affine{}, err
	}

	//byteX is big-endian, bitsX is little endian
	var bitsX [LenOfPubkey * 8]frontend.Variable
	for i := 0; i < LenOfPubkey; i++ {
		oneByteBitsVar := bits.ToBinary(api, byteX[LenOfPubkey-i-1], bits.WithNbDigits(8))
		copy(bitsX[i*8:(i+1)*8], oneByteBitsVar)
	}

	//Y² = X³ + aX + b
	x := fpField.FromBits(bitsX[:]...)
	b := fpField.NewElement(4)
	xSquare := fpField.Mul(x, x)
	xCubic := fpField.Mul(xSquare, x)
	xSum := fpField.Add(xCubic, b)
	y := fpField.Sqrt(xSum)

	negY := fpField.Neg(y)
	negY = fpField.Reduce(negY)
	cmpRes := fpField.Cmp(y, negY) //maybe -1, 0, 1
	cmpRes = api.Add(cmpRes, 1)    //change to 0,1,2
	cmpResBits := api.ToBinary(cmpRes, 2)
	lexicographicallyLargest := api.Select(cmpResBits[1], 1, 0) //if y > -y, res =1, else res = 0

	/*
		Lookup2(lexicographicallyLargest, isLargest, a, b, c, d)
		lexicographicallyLargest = 0, isLargest = 0  output a, y = y
		lexicographicallyLargest = 1, isLargest = 0  output b, y = -y
		lexicographicallyLargest = 0, isLargest = 1  output c, y= -y
		lexicographicallyLargest = 1, isLargest = 1  output d, y = y
	*/
	yFinal := fpField.Lookup2(lexicographicallyLargest, isLargest, y, negY, negY, y)

	g1Affine := G1Affine{
		X: *x,
		Y: *yFinal,
	}

	return g1Affine, nil
}
