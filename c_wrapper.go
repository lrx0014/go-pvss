package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"unsafe"

	"github.com/stars-labs/go-pvss/crypto/secp256k1"
	"github.com/stars-labs/go-pvss/pvss"
)

type dealerHandle struct {
	dealer     *pvss.Dealer
	privateKey *ecdsa.PrivateKey
}

var (
	mu         sync.Mutex
	nextID     uint64 = 1
	dealers           = make(map[uint64]*dealerHandle)
	shareBoxes        = make(map[uint64]*pvss.DistributionSharesBox)
	decShares         = make(map[uint64]*pvss.DecryptedShare)
)

type dealerInfo struct {
	ID               uint64 `json:"id"`
	PrivateKey       string `json:"private_key"`
	PublicKeyX       string `json:"public_key_x"`
	PublicKeyY       string `json:"public_key_y"`
	DecryptedShareID uint64 `json:"decrypted_share_id,omitempty"`
}

type newDealerResponse struct {
	Dealer dealerInfo `json:"dealer"`
}

type createSharesResponse struct {
	DealerID     uint64       `json:"dealer_id"`
	ShareBoxID   uint64       `json:"share_box_id"`
	Threshold    int          `json:"threshold"`
	Participants []dealerInfo `json:"participants"`
}

type createWithPubKeysResponse struct {
	ShareBox   pvss.ShareBoxPayload `json:"share_box"`
	ShareBoxID uint64               `json:"share_box_id"`
	Shares     []pvss.SharePayload  `json:"shares"`
	Threshold  int                  `json:"threshold"`
	PubKeys    []pvss.PointHex      `json:"pub_keys"`
	DealerID   uint64               `json:"dealer_id"`
	Secret     string               `json:"secret"`
}

type verifyShareResponse struct {
	OK bool `json:"ok"`
}

type reconstructResponse struct {
	Secret string `json:"secret"`
}

type pointInput struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func registerDealer(priv *ecdsa.PrivateKey) (uint64, *dealerHandle) {
	handle := &dealerHandle{
		dealer:     pvss.NewDealer(priv),
		privateKey: priv,
	}
	mu.Lock()
	id := nextID
	nextID++
	dealers[id] = handle
	mu.Unlock()
	return id, handle
}

func registerShareBox(sb *pvss.DistributionSharesBox) uint64 {
	mu.Lock()
	id := nextID
	nextID++
	shareBoxes[id] = sb
	mu.Unlock()
	return id
}

func registerDecryptedShare(ds *pvss.DecryptedShare) uint64 {
	mu.Lock()
	id := nextID
	nextID++
	decShares[id] = ds
	mu.Unlock()
	return id
}

func pubKeysFromJSON(data string) ([]*ecdsa.PublicKey, []pvss.PointHex, error) {
	var inputs []pointInput
	if err := json.Unmarshal([]byte(data), &inputs); err != nil {
		return nil, nil, err
	}
	pks := make([]*ecdsa.PublicKey, 0, len(inputs))
	points := make([]pvss.PointHex, 0, len(inputs))
	for _, in := range inputs {
		xBytes, err := hex.DecodeString(in.X)
		if err != nil {
			return nil, nil, err
		}
		yBytes, err := hex.DecodeString(in.Y)
		if err != nil {
			return nil, nil, err
		}
		pk := &ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		pks = append(pks, pk)
		points = append(points, pvss.PointHex{X: in.X, Y: in.Y})
	}
	return pks, points, nil
}

func getDealer(id uint64) (*dealerHandle, bool) {
	mu.Lock()
	defer mu.Unlock()
	d, ok := dealers[id]
	return d, ok
}

func getShareBox(id uint64) (*pvss.DistributionSharesBox, bool) {
	mu.Lock()
	defer mu.Unlock()
	sb, ok := shareBoxes[id]
	return sb, ok
}

func getDecShare(id uint64) (*pvss.DecryptedShare, bool) {
	mu.Lock()
	defer mu.Unlock()
	ds, ok := decShares[id]
	return ds, ok
}

func dealerInfoFrom(id uint64, priv *ecdsa.PrivateKey) dealerInfo {
	return dealerInfo{
		ID:         id,
		PrivateKey: hex.EncodeToString(priv.D.Bytes()),
		PublicKeyX: hex.EncodeToString(priv.X.Bytes()),
		PublicKeyY: hex.EncodeToString(priv.Y.Bytes()),
	}
}

func marshalError(err error) *C.char {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return C.CString(string(b))
}

func marshalToCString(v interface{}) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return marshalError(err)
	}
	return C.CString(string(b))
}

//export NewDealer
func NewDealer() *C.char {
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return marshalError(err)
	}
	id, _ := registerDealer(priv)
	info := dealerInfoFrom(id, priv)
	return marshalToCString(newDealerResponse{Dealer: info})
}

//export LoadDealerFromPriv
func LoadDealerFromPriv(privHex *C.char) *C.char {
	raw, err := hex.DecodeString(C.GoString(privHex))
	if err != nil {
		return marshalError(err)
	}
	d := new(big.Int).SetBytes(raw)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
		},
		D: d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = secp256k1.S256().ScalarBaseMult(d.Bytes())
	id, _ := registerDealer(priv)
	info := dealerInfoFrom(id, priv)
	return marshalToCString(newDealerResponse{Dealer: info})
}

//export CreateShares
func CreateShares(dealerID C.ulonglong, secret *C.char, participants C.int, threshold C.int) *C.char {
	dHandle, ok := getDealer(uint64(dealerID))
	if !ok {
		return marshalError(fmt.Errorf("unknown dealer id %d", uint64(dealerID)))
	}
	n := int(participants)
	t := int(threshold)
	if n <= 0 {
		return marshalError(fmt.Errorf("participants must be greater than zero"))
	}
	if t <= 0 || t > n {
		return marshalError(fmt.Errorf("threshold must be between 1 and participants"))
	}

	secretBytes := []byte(C.GoString(secret))
	secretInt := new(big.Int).SetBytes(secretBytes)

	pks := make([]*ecdsa.PublicKey, 0, n)
	participantInfos := make([]dealerInfo, 0, n)
	participantHandles := make([]*dealerHandle, 0, n)
	for i := 0; i < n; i++ {
		priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		if err != nil {
			return marshalError(err)
		}
		id, handle := registerDealer(priv)
		pks = append(pks, &handle.privateKey.PublicKey)
		participantHandles = append(participantHandles, handle)
		participantInfos = append(participantInfos, dealerInfoFrom(id, priv))
	}

	sharebox, err := dHandle.dealer.DistributeSecret(secretInt, pks, t)
	if err != nil {
		return marshalError(err)
	}

	shareBoxID := registerShareBox(sharebox)
	for i, p := range participantHandles {
		decShare, err := p.dealer.ExtractSecretShare(sharebox)
		if err != nil {
			return marshalError(err)
		}
		decShareID := registerDecryptedShare(decShare)
		participantInfos[i].DecryptedShareID = decShareID
	}

	resp := createSharesResponse{
		DealerID:     uint64(dealerID),
		ShareBoxID:   shareBoxID,
		Threshold:    t,
		Participants: participantInfos,
	}
	return marshalToCString(resp)
}

//export CreateSharesWithPubKeys
func CreateSharesWithPubKeys(dealerID C.ulonglong, secret *C.char, pubKeysJSON *C.char, threshold C.int) *C.char {
	dHandle, ok := getDealer(uint64(dealerID))
	if !ok {
		return marshalError(fmt.Errorf("unknown dealer id %d", uint64(dealerID)))
	}
	pks, pkPoints, err := pubKeysFromJSON(C.GoString(pubKeysJSON))
	if err != nil {
		return marshalError(err)
	}
	t := int(threshold)
	if t <= 0 || t > len(pks) {
		return marshalError(fmt.Errorf("threshold must be between 1 and %d", len(pks)))
	}
	secretBytes := []byte(C.GoString(secret))
	secretInt := new(big.Int).SetBytes(secretBytes)

	sharebox, err := dHandle.dealer.DistributeSecret(secretInt, pks, t)
	if err != nil {
		return marshalError(err)
	}
	shareBoxID := registerShareBox(sharebox)

	sharePayloads := make([]pvss.SharePayload, 0, len(sharebox.Shares))
	for _, s := range sharebox.Shares {
		sharePayloads = append(sharePayloads, pvss.EncodeShare(s))
	}

	resp := createWithPubKeysResponse{
		ShareBox:   pvss.EncodeShareBox(sharebox),
		ShareBoxID: shareBoxID,
		Shares:     sharePayloads,
		Threshold:  t,
		PubKeys:    pkPoints,
		DealerID:   uint64(dealerID),
		Secret:     string(secretBytes),
	}
	return marshalToCString(resp)
}

//export VerifyShare
func VerifyShare(decShareID C.ulonglong) *C.char {
	ds, ok := getDecShare(uint64(decShareID))
	if !ok {
		return marshalError(fmt.Errorf("unknown decrypted share id %d", uint64(decShareID)))
	}
	okRes := pvss.VerifyDecryptedShare(ds)
	return marshalToCString(verifyShareResponse{OK: okRes})
}

//export Reconstruct
func Reconstruct(shareBoxID C.ulonglong, decShareIDsJSON *C.char) *C.char {
	sb, ok := getShareBox(uint64(shareBoxID))
	if !ok {
		return marshalError(fmt.Errorf("unknown share box id %d", uint64(shareBoxID)))
	}
	var ids []uint64
	if err := json.Unmarshal([]byte(C.GoString(decShareIDsJSON)), &ids); err != nil {
		return marshalError(fmt.Errorf("parse decrypted share ids: %w", err))
	}
	if len(ids) < len(sb.Commitments) {
		return marshalError(fmt.Errorf("need at least %d decrypted shares", len(sb.Commitments)))
	}

	decList := make([]*pvss.DecryptedShare, 0, len(ids))
	for _, id := range ids {
		ds, ok := getDecShare(id)
		if !ok {
			return marshalError(fmt.Errorf("unknown decrypted share id %d", id))
		}
		decList = append(decList, ds)
	}

	secret := pvss.ReconstructSecret(decList, sb.U)
	if secret == nil {
		return marshalError(fmt.Errorf("secret reconstruction failed"))
	}
	return marshalToCString(reconstructResponse{Secret: string(secret.Bytes())})
}

//export VerifyEncryptedSharePayload
func VerifyEncryptedSharePayload(boxJSON *C.char, shareJSON *C.char) *C.char {
	var box pvss.ShareBoxPayload
	var share pvss.SharePayload
	if err := json.Unmarshal([]byte(C.GoString(boxJSON)), &box); err != nil {
		return marshalError(err)
	}
	if err := json.Unmarshal([]byte(C.GoString(shareJSON)), &share); err != nil {
		return marshalError(err)
	}
	ok, err := pvss.VerifyEncryptedSharePayload(box, share)
	if err != nil {
		return marshalError(err)
	}
	return marshalToCString(verifyShareResponse{OK: ok})
}

//export DecryptSharePayload
func DecryptSharePayload(dealerID C.ulonglong, shareJSON *C.char) *C.char {
	dHandle, ok := getDealer(uint64(dealerID))
	if !ok {
		return marshalError(fmt.Errorf("unknown dealer id %d", uint64(dealerID)))
	}
	var sharePayload pvss.SharePayload
	if err := json.Unmarshal([]byte(C.GoString(shareJSON)), &sharePayload); err != nil {
		return marshalError(err)
	}
	share, err := pvss.DecodeSharePayload(sharePayload)
	if err != nil {
		return marshalError(err)
	}
	box := &pvss.DistributionSharesBox{
		Shares: []*pvss.Share{share},
	}
	decShare, err := dHandle.dealer.ExtractSecretShare(box)
	if err != nil {
		return marshalError(err)
	}
	return marshalToCString(pvss.EncodeDecryptedShare(decShare))
}

//export VerifyDecryptedSharePayload
func VerifyDecryptedSharePayload(decShareJSON *C.char) *C.char {
	var payload pvss.DecryptedSharePayload
	if err := json.Unmarshal([]byte(C.GoString(decShareJSON)), &payload); err != nil {
		return marshalError(err)
	}
	ok, err := pvss.VerifyDecryptedSharePayload(payload)
	if err != nil {
		return marshalError(err)
	}
	return marshalToCString(verifyShareResponse{OK: ok})
}

//export ReconstructFromPayload
func ReconstructFromPayload(boxJSON *C.char, decSharesJSON *C.char) *C.char {
	var box pvss.ShareBoxPayload
	if err := json.Unmarshal([]byte(C.GoString(boxJSON)), &box); err != nil {
		return marshalError(err)
	}
	var decPayloads []pvss.DecryptedSharePayload
	if err := json.Unmarshal([]byte(C.GoString(decSharesJSON)), &decPayloads); err != nil {
		return marshalError(err)
	}
	secret, err := pvss.ReconstructFromPayload(box, decPayloads)
	if err != nil {
		return marshalError(err)
	}
	if secret == nil {
		return marshalError(fmt.Errorf("secret reconstruction failed"))
	}
	return marshalToCString(reconstructResponse{Secret: string(secret.Bytes())})
}

//export FreeCString
func FreeCString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
