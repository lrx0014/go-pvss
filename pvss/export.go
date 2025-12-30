package pvss

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// PointHex is a hex-encoded point payload.
type PointHex struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// SharePayload carries an encrypted share and its proof.
type SharePayload struct {
	PK        PointHex `json:"pk"`
	Position  int      `json:"position"`
	S         PointHex `json:"s"`
	Challenge string   `json:"challenge"`
	Response  string   `json:"response"`
}

// DecryptedSharePayload carries a decrypted share and its proof.
type DecryptedSharePayload struct {
	PK        PointHex `json:"pk"`
	Position  int      `json:"position"`
	S         PointHex `json:"s"`
	Y         PointHex `json:"y"`
	Challenge string   `json:"challenge"`
	Response  string   `json:"response"`
}

// ShareBoxPayload contains the commitments and masked secret U.
type ShareBoxPayload struct {
	Commitments []PointHex `json:"commitments"`
	U           string     `json:"u"`
}

func pointToHex(p *Point) PointHex {
	return PointHex{
		X: hex.EncodeToString(p.X.Bytes()),
		Y: hex.EncodeToString(p.Y.Bytes()),
	}
}

func pointFromHex(h PointHex) (*Point, error) {
	x, err := hex.DecodeString(h.X)
	if err != nil {
		return nil, err
	}
	y, err := hex.DecodeString(h.Y)
	if err != nil {
		return nil, err
	}
	return &Point{X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

func bigFromHex(s string) (*big.Int, error) {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, errors.New("invalid hex big integer")
	}
	return b, nil
}

// EncodeShareBox turns a DistributionSharesBox into a transport-friendly payload.
func EncodeShareBox(box *DistributionSharesBox) ShareBoxPayload {
	commitments := make([]PointHex, 0, len(box.Commitments))
	for _, c := range box.Commitments {
		commitments = append(commitments, pointToHex(c))
	}
	return ShareBoxPayload{
		Commitments: commitments,
		U:           hex.EncodeToString(box.U.Bytes()),
	}
}

// EncodeShare turns an encrypted share into a payload.
func EncodeShare(s *Share) SharePayload {
	return SharePayload{
		PK:        pointToHex(&Point{s.PK.X, s.PK.Y}),
		Position:  s.Position,
		S:         pointToHex(s.S),
		Challenge: hex.EncodeToString(s.challenge.Bytes()),
		Response:  hex.EncodeToString(s.response.Bytes()),
	}
}

// EncodeDecryptedShare turns a decrypted share into a payload.
func EncodeDecryptedShare(ds *DecryptedShare) DecryptedSharePayload {
	return DecryptedSharePayload{
		PK:        pointToHex(&Point{ds.PK.X, ds.PK.Y}),
		Position:  ds.Position,
		S:         pointToHex(ds.S),
		Y:         pointToHex(ds.Y),
		Challenge: hex.EncodeToString(ds.challenge.Bytes()),
		Response:  hex.EncodeToString(ds.response.Bytes()),
	}
}

// DecodeSharePayload builds a Share from payload data.
func DecodeSharePayload(p SharePayload) (*Share, error) {
	pkPoint, err := pointFromHex(p.PK)
	if err != nil {
		return nil, err
	}
	sPoint, err := pointFromHex(p.S)
	if err != nil {
		return nil, err
	}
	challenge, err := hex.DecodeString(p.Challenge)
	if err != nil {
		return nil, err
	}
	response, err := hex.DecodeString(p.Response)
	if err != nil {
		return nil, err
	}
	return &Share{
		PK: &ecdsa.PublicKey{
			Curve: theCurve,
			X:     pkPoint.X,
			Y:     pkPoint.Y,
		},
		Position:  p.Position,
		S:         sPoint,
		challenge: new(big.Int).SetBytes(challenge),
		response:  new(big.Int).SetBytes(response),
	}, nil
}

// DecodeDecryptedSharePayload builds a DecryptedShare from payload data.
func DecodeDecryptedSharePayload(p DecryptedSharePayload) (*DecryptedShare, error) {
	pkPoint, err := pointFromHex(p.PK)
	if err != nil {
		return nil, err
	}
	sPoint, err := pointFromHex(p.S)
	if err != nil {
		return nil, err
	}
	yPoint, err := pointFromHex(p.Y)
	if err != nil {
		return nil, err
	}
	challenge, err := hex.DecodeString(p.Challenge)
	if err != nil {
		return nil, err
	}
	response, err := hex.DecodeString(p.Response)
	if err != nil {
		return nil, err
	}
	return &DecryptedShare{
		PK: &ecdsa.PublicKey{
			Curve: theCurve,
			X:     pkPoint.X,
			Y:     pkPoint.Y,
		},
		Position:  p.Position,
		S:         sPoint,
		Y:         yPoint,
		challenge: new(big.Int).SetBytes(challenge),
		response:  new(big.Int).SetBytes(response),
	}, nil
}

// DecodeShareBoxPayload builds a DistributionSharesBox from payload data.
func DecodeShareBoxPayload(p ShareBoxPayload) (*DistributionSharesBox, error) {
	commitments := make([]*Point, 0, len(p.Commitments))
	for _, c := range p.Commitments {
		pc, err := pointFromHex(c)
		if err != nil {
			return nil, err
		}
		commitments = append(commitments, pc)
	}
	uBytes, err := hex.DecodeString(p.U)
	if err != nil {
		return nil, err
	}
	return &DistributionSharesBox{
		Commitments: commitments,
		U:           new(big.Int).SetBytes(uBytes),
	}, nil
}

// VerifyEncryptedSharePayload verifies a single encrypted share against commitments.
func VerifyEncryptedSharePayload(box ShareBoxPayload, share SharePayload) (bool, error) {
	sb, err := DecodeShareBoxPayload(box)
	if err != nil {
		return false, err
	}
	s, err := DecodeSharePayload(share)
	if err != nil {
		return false, err
	}
	return verifyEncryptedShareWithCommitments(sb.Commitments, s), nil
}

// VerifyDecryptedSharePayload verifies a decrypted share payload.
func VerifyDecryptedSharePayload(ds DecryptedSharePayload) (bool, error) {
	dsStruct, err := DecodeDecryptedSharePayload(ds)
	if err != nil {
		return false, err
	}
	hasher := sha3.New256()
	return DLEQVerify(hasher, G1, &Point{dsStruct.PK.X, dsStruct.PK.Y}, dsStruct.S, dsStruct.Y, dsStruct.challenge, dsStruct.response), nil
}

// ReconstructFromPayload reconstructs the secret from payloads.
func ReconstructFromPayload(box ShareBoxPayload, shares []DecryptedSharePayload) (*big.Int, error) {
	sb, err := DecodeShareBoxPayload(box)
	if err != nil {
		return nil, err
	}
	decShares := make([]*DecryptedShare, 0, len(shares))
	for _, p := range shares {
		ds, err := DecodeDecryptedSharePayload(p)
		if err != nil {
			return nil, err
		}
		decShares = append(decShares, ds)
	}
	return ReconstructSecret(decShares, sb.U), nil
}

// verifyEncryptedShareWithCommitments checks a single share with commitments.
func verifyEncryptedShareWithCommitments(commitments []*Point, share *Share) bool {
	if len(commitments) == 0 {
		return false
	}
	hasher := sha3.New256()
	bigi, bigj, bigij := new(big.Int), new(big.Int), new(big.Int)
	H := &Point{Hx, Hy}

	Xix, Xiy, Cijx, Cijy := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	Xix.Set(commitments[0].X)
	Xiy.Set(commitments[0].Y)
	for j := 1; j < len(commitments); j++ {
		bigi.SetInt64(int64(share.Position))
		bigj.SetInt64(int64(j))
		bigij.Exp(bigi, bigj, secp256k1N)
		Cijx, Cijy = theCurve.ScalarMult(commitments[j].X, commitments[j].Y, bigij.Bytes())
		Xix, Xiy = theCurve.Add(Xix, Xiy, Cijx, Cijy)
	}
	return DLEQVerify(hasher, H, &Point{X: Xix, Y: Xiy}, &Point{X: share.PK.X, Y: share.PK.Y}, share.S, share.challenge, share.response)
}
