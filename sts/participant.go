package sts

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
)

// Participant model
type Participant struct {
	g *big.Int
	p *big.Int

	x  *big.Int
	ax *big.Int

	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
	SessionKey []byte
}

func (par *Participant) GenX() *big.Int {
	var err error

	tmp := new(big.Int).Sub(par.p, big.NewInt(1))
	par.x, err = rand.Int(rand.Reader, tmp)
	common.CheckErr(err)

	par.ax = new(big.Int).Exp(par.g, par.x, par.p)

	return par.ax
}

func (par *Participant) GenX2(ay *big.Int) (*big.Int, []byte) {
	var err error

	// Here we denote ax = a^x from protocol, where x is ALWAYS this
	// participant's nonce and y is other participant's one

	// Generate nonce the same way
	ax := par.GenX()

	// Generate "pre" session key
	preSessionKey := new(big.Int).Exp(ay, par.x, par.p)

	// Use HKDF to get AES key
	par.SessionKey, err = common.Hkdf(preSessionKey.Bytes(), aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// fmt.Printf("SessionKey = %x\n", par.SessionKey)

	// Create a signature
	message := append(ax.Bytes(), ay.Bytes()...)

	// Make a digest to sign
	digest := sha256.Sum256(message)

	// Sign
	signature, err := rsa.SignPSS(rand.Reader, par.PrivateKey, crypto.SHA256, digest[:], nil)
	common.CheckErr(err)

	// fmt.Printf("Signature = %x\n", signature)

	// Encrypt signature
	ct, err := common.Encrypt(signature, par.SessionKey)
	common.CheckErr(err)

	// fmt.Printf("ct = %x\n", ct)

	return ax, ct
}

func (par *Participant) Check(ay *big.Int, ct []byte, pk *rsa.PublicKey) ([]byte, error) {
	var err error

	// Generate "pre" session key
	preSessionKey := new(big.Int).Exp(ay, par.x, par.p)

	// Use HKDF to get AES key
	par.SessionKey, err = common.Hkdf(preSessionKey.Bytes(), aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("SessionKey = %x\n", par.SessionKey)
	// fmt.Printf("ct = %x\n", ct)

	// Decrypt signature
	signature, err := common.Decrypt(ct, par.SessionKey)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("Signature = %x\n", signature)

	message := append(ay.Bytes(), par.ax.Bytes()...)

	// Make a digest to sign
	digest := sha256.Sum256(message)

	if err = rsa.VerifyPSS(pk, crypto.SHA256, digest[:], signature, nil); err != nil {
		par.SessionKey = make([]byte, 16)
		return nil, err
	}

	// If all good, create a signature
	message = append(par.ax.Bytes(), ay.Bytes()...)

	// Make a digest to sign
	digest = sha256.Sum256(message)

	// Sign
	signature, err = rsa.SignPSS(rand.Reader, par.PrivateKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return nil, err
	}

	// Encrypt signature
	newCt, err := common.Encrypt(signature, par.SessionKey)
	if err != nil {
		return nil, err
	}

	return newCt, nil
}

func (par *Participant) Check2(ay *big.Int, ct []byte, pk *rsa.PublicKey) error {
	signature, err := common.Decrypt(ct, par.SessionKey)
	if err != nil {
		return err
	}

	message := append(ay.Bytes(), par.ax.Bytes()...)

	// Make a digest to sign
	digest := sha256.Sum256(message)

	if err := rsa.VerifyPSS(pk, crypto.SHA256, digest[:], signature, nil); err != nil {
		par.SessionKey = make([]byte, 16)
		return err
	}

	return nil
}

func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)
	var err error

	par.p = p
	par.g = g

	par.PrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil
	}

	par.PublicKey = &par.PrivateKey.PublicKey

	return par
}
