package starkex

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/huandu/xstrings"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

const fieldPrime = "3618502788666131213697322783095070105623107215331596699973092056135872020481"

// const FIELD_GEN = 3

const ALPHA = 1

// const BETA = "3141592653589793238462643383279502884197169399375105820974944592307816406665"
const ecOrder = "3618502788666131213697322783095070105526743751716087489154079457884512865583"

var constantPoints = [][]string{
	[]string{
		"2089986280348253421170679821480865132823066470938446095505822317253594081284",
		"1713931329540660377023406109199410414810705867260802078187082345529207694986",
	},
	[]string{
		"874739451078007766457464989774322083649278607533249481151382481072868806602",
		"152666792071518830868575557812948353041420400780739481342941381225525861407",
	},
}

// N_ELEMENT_BITS_ECDSA math.floor(math.log(FIELD_PRIME, 2))
var N_ELEMENT_BITS_ECDSA = big.NewInt(251)

//var SHIFT_POINT = CONSTANT_POINTS[0]

var ecGen = constantPoints[1]

type XyCoordinates struct {
	X string
	Y string
}

func Sign(privateKeyHex string, payload string) string {
	priKey, _ := new(big.Int).SetString(privateKeyHex, 16)
	msgHash, _ := new(big.Int).SetString(payload, 0)
	seed := 0
	eg1 := new(big.Int)
	eg2 := new(big.Int)

	eg1.SetString(ecGen[0], 0)
	eg2.SetString(ecGen[1], 0)

	egGenInt := [2]*big.Int{eg1, eg2}

	ecOrderInt := new(big.Int)
	ecOrderInt.SetString(ecOrder, 0)
	fieldPrimeInt := new(big.Int)
	fieldPrimeInt.SetString(fieldPrime, 0)

	nBit := big.NewInt(0).Exp(big.NewInt(2), N_ELEMENT_BITS_ECDSA, nil)
	for {
		k := GenerateKRfc6979(msgHash, priKey, seed)
		//	Update seed for next iteration in case the value of k is bad.
		if seed == 0 {
			seed = 1
		} else {
			seed += 1
		}
		// Cannot fail because 0 < k < EC_ORDER and EC_ORDER is prime.
		x := ecMult(k, egGenInt, ALPHA, fieldPrimeInt)[0]
		// !(1 <= x < 2 ** N_ELEMENT_BITS_ECDSA)
		if !(x.Cmp(one) > 0 && x.Cmp(nBit) < 0) {
			continue
		}
		// msg_hash + r * priv_key
		x1 := big.NewInt(0).Add(msgHash, big.NewInt(0).Mul(x, priKey))
		// (msg_hash + r * priv_key) % EC_ORDER == 0
		if big.NewInt(0).Mod(x1, ecOrderInt).Cmp(zero) == 0 {
			continue
		}
		// w = div_mod(k, msg_hash + r * priv_key, EC_ORDER)
		w := divMod(k, x1, ecOrderInt)
		// not (1 <= w < 2 ** N_ELEMENT_BITS_ECDSA)
		if !(w.Cmp(one) > 0 && w.Cmp(nBit) < 0) {
			continue
		}
		s1 := divMod(one, w, ecOrderInt)
		return SerializeSignature(x, s1)
	}
}

func GenerateKRfc6979(msgHash, priKey *big.Int, seed int) *big.Int {
	msgHash = big.NewInt(0).Set(msgHash) // copy
	bitMod := msgHash.BitLen() % 8
	if bitMod <= 4 && bitMod >= 1 && msgHash.BitLen() > 248 {
		msgHash.Mul(msgHash, big.NewInt(16))
	}
	var extra []byte
	if seed > 0 {
		buf := new(bytes.Buffer)
		var data interface{}
		if seed < 256 {
			data = uint8(seed)
		} else if seed < 65536 {
			data = uint16(seed)
		} else if seed < 4294967296 {
			data = uint32(seed)
		} else {
			data = uint64(seed)
		}
		_ = binary.Write(buf, binary.BigEndian, data)
		extra = buf.Bytes()
	}
	ecOrderInt := new(big.Int)
	ecOrderInt.SetString(ecOrder, 0)
	return generateSecret(ecOrderInt, priKey, sha256.New, msgHash.Bytes(), extra)
}

func PrivateToPublicKeyPair(privateKeyHex string) (XyCoordinates, error) {
	privateKeyInt := new(big.Int)
	privateKeyInt.SetString(privateKeyHex, 16)

	eg1 := new(big.Int)
	eg2 := new(big.Int)

	eg1.SetString(ecGen[0], 0)
	eg2.SetString(ecGen[1], 0)

	egGenInt := [2]*big.Int{eg1, eg2}

	fieldPrimeInt := new(big.Int)
	fieldPrimeInt.SetString(fieldPrime, 0)

	publicKeyPair := ecMult(privateKeyInt, egGenInt, ALPHA, fieldPrimeInt)

	x := publicKeyPair[0]
	y := publicKeyPair[1]
	return XyCoordinates{
		X: fmt.Sprintf("%x", x),
		Y: fmt.Sprintf("%x", y),
	}, nil
}

// ecMult Multiplies by m a point on the elliptic curve with equation y^2 = x^3 + alpha*x + beta mod p.
// Assumes the point is given in affine form (x, y) and that 0 < m < order(point).
func ecMult(m *big.Int, point [2]*big.Int, alpha int, p *big.Int) [2]*big.Int {
	if m.Cmp(one) == 0 {
		return point
	}
	//return point
	if big.NewInt(0).Mod(m, two).Cmp(zero) == 0 {
		return ecMult(big.NewInt(0).Quo(m, two), ecDouble(point, alpha, p), alpha, p)
	}
	return eccAdd(ecMult(big.NewInt(0).Sub(m, one), point, alpha, p), point, p)
}

// ecDouble Doubles a point on an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p.
func ecDouble(point [2]*big.Int, alpha int, p *big.Int) [2]*big.Int {
	// m = div_mod(3 * point[0] * point[0] + alpha, 2 * point[1], p)
	p1 := big.NewInt(3)
	p1.Mul(p1, big.NewInt(0).Mul(point[0], point[0]))
	p1.Add(p1, big.NewInt(int64(alpha)))
	p2 := big.NewInt(0)
	p2.Mul(two, point[1])
	m := divMod(p1, p2, p)
	// x = (m * m - 2 * point[0]) % p
	x := big.NewInt(0)
	x.Sub(big.NewInt(0).Mul(m, m), big.NewInt(0).Mul(two, point[0]))
	x.Mod(x, p)
	// y = (m * (point[0] - x) - point[1]) % p
	y := big.NewInt(0)
	y.Sub(big.NewInt(0).Mul(m, big.NewInt(0).Sub(point[0], x)), point[1])
	y.Mod(y, p)
	return [2]*big.Int{x, y}
}

// Assumes the point is given in affine form (x, y) and has y != 0.

// eccAdd Gets two points on an elliptic curve mod p and returns their sum.
// Assumes the points are given in affine form (x, y) and have different x coordinates.
func eccAdd(point1 [2]*big.Int, point2 [2]*big.Int, p *big.Int) [2]*big.Int {
	// m = div_mod(point1[1] - point2[1], point1[0] - point2[0], p)
	d1 := big.NewInt(0).Sub(point1[1], point2[1])
	d2 := big.NewInt(0).Sub(point1[0], point2[0])
	m := divMod(d1, d2, p)

	// x = (m * m - point1[0] - point2[0]) % p
	x := big.NewInt(0)
	x.Sub(big.NewInt(0).Mul(m, m), point1[0])
	x.Sub(x, point2[0])
	x.Mod(x, p)

	// y := (m*(point1[0]-x) - point1[1]) % p
	y := big.NewInt(0)
	y.Mul(m, big.NewInt(0).Sub(point1[0], x))
	y.Sub(y, point1[1])
	y.Mod(y, p)

	return [2]*big.Int{x, y}
}

// divMod Finds a nonnegative integer 0 <= x < p such that (m * x) % p == n
func divMod(n, m, p *big.Int) *big.Int {
	a, _, _ := igcDex(m, p)
	// (n * a) % p
	tmp := big.NewInt(0).Mul(n, a)
	return tmp.Mod(tmp, p)
}

func igcDex(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if a.Cmp(zero) == 0 && b.Cmp(zero) == 0 {
		return big.NewInt(0), big.NewInt(1), big.NewInt(0)
	}
	if a.Cmp(zero) == 0 {
		return big.NewInt(0), big.NewInt(0).Quo(b, big.NewInt(0).Abs(b)), big.NewInt(0).Abs(b)
	}
	if b.Cmp(zero) == 0 {
		return big.NewInt(0).Quo(a, big.NewInt(0).Abs(a)), big.NewInt(0), big.NewInt(0).Abs(a)
	}
	xSign := big.NewInt(1)
	ySign := big.NewInt(1)
	if a.Cmp(zero) == -1 {
		a, xSign = a.Neg(a), big.NewInt(-1)
	}
	if b.Cmp(zero) == -1 {
		b, ySign = b.Neg(b), big.NewInt(-1)
	}
	x, y, r, s := big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(1)
	for b.Cmp(zero) > 0 {
		c, q := big.NewInt(0).Mod(a, b), big.NewInt(0).Quo(a, b)
		a, b, r, s, x, y = b, c, big.NewInt(0).Sub(x, big.NewInt(0).Mul(q, r)), big.NewInt(0).Sub(y, big.NewInt(0).Mul(big.NewInt(0).Neg(q), s)), r, s
	}
	return x.Mul(x, xSign), y.Mul(y, ySign), a
}

// SerializeSignature Convert a Sign from an r, s pair to a 32-byte hex string.
func SerializeSignature(r, s *big.Int) string {
	return IntToHex32(r) + IntToHex32(s)
}

// IntToHex32 Normalize to a 32-byte hex string without 0x prefix.
func IntToHex32(x *big.Int) string {
	str := x.Text(16)
	return xstrings.RightJustify(str, 64, "0")
}
