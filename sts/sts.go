package sts

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
)

type KeyPair struct {
	N *big.Int
	E *int
}

type Participant struct {
	PrivateKey *rsa.PrivateKey

	g *big.Int
	p *big.Int

	PublicKey  KeyPair
	SecretKey  *big.Int
	SessionKey *big.Int
}

func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)
	var err error

	par.p = p
	par.g = g

	par.PrivateKey, err = rsa.GenerateKey(rand.Reader, 128)
	common.CheckErr(err)

	par.SecretKey = par.PrivateKey.D
	par.PublicKey = KeyPair{par.PrivateKey.N, &par.PrivateKey.E}

	return par
}

func Demo() {
}
