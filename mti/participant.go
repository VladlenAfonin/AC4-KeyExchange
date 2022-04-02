package mti

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
	"github.com/mikhirev/gostribog"
	"golang.org/x/crypto/hkdf"
)

// Participant model.
type Participant struct {
	g *big.Int
	p *big.Int

	x *big.Int

	PublicKey  *big.Int
	SecretKey  *big.Int
	SessionKey *big.Int
}

// Generates session key from another participant's public key and nonce.
func (par *Participant) GenerateSessionKey(publicKey, nonce *big.Int) {
	mtoa := new(big.Int).Exp(nonce, par.SecretKey, par.p)
	ptox := new(big.Int).Exp(publicKey, par.x, par.p)

	sessionKey := new(big.Int).Mul(ptox, mtoa)
	sessionKey.Mod(sessionKey, par.p)

	hash := gostribog.New256

	hkdf := hkdf.New(hash, sessionKey.Bytes(), nil, nil)

	par.SessionKey = new(big.Int)
	buf := make([]byte, 16) // take 128 bits (AES key, for example)

	_, err := io.ReadFull(hkdf, buf)
	common.CheckErr(err)

	par.SessionKey.SetBytes(buf)
}

// Generates private and public nonces. Returns public nonce.
func (par *Participant) GenX() *big.Int {
	var err error

	tmp := new(big.Int).Sub(par.p, big.NewInt(1))
	par.x, err = rand.Int(rand.Reader, tmp)
	common.CheckErr(err)

	m := new(big.Int).Exp(par.g, par.x, par.p)

	return m
}

// Initializes a new Participant.
func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)

	par.p = p
	par.g = g

	tmp := new(big.Int).Sub(p, big.NewInt(1))
	sk, err := rand.Int(rand.Reader, tmp)
	common.CheckErr(err)

	par.SecretKey = sk
	par.PublicKey = new(big.Int)
	par.PublicKey.Exp(g, sk, p)

	return par
}
