package diffie

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
	"golang.org/x/crypto/hkdf"
)

// Participant model.
type Participant struct {
	g *big.Int
	p *big.Int

	PublicKey  *big.Int
	SecretKey  *big.Int
	SessionKey *big.Int
}

// Generates session key from another participant's public key.
func (par *Participant) GenerateSessionKey(publicKey *big.Int) {
	sessionKey := new(big.Int)
	sessionKey.Exp(publicKey, par.SecretKey, par.p)

	hash := sha256.New
	hkdf := hkdf.New(hash, sessionKey.Bytes(), nil, nil)

	par.SessionKey = new(big.Int)
	buf := make([]byte, 16) // take 128 bits (AES key, for example)

	_, err := io.ReadFull(hkdf, buf)
	common.CheckErr(err, common.ErrorReading)

	par.SessionKey.SetBytes(buf)
}

// Initializes a new Participant.
func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)

	par.p = p
	par.g = g

	// I know it's horrible
	tmp := big.NewInt(0).Sub(p, big.NewInt(1))

	sk, err := rand.Int(rand.Reader, tmp)
	common.CheckErr(err, common.ErrorPrime)

	par.SecretKey = sk
	par.PublicKey = new(big.Int)
	par.PublicKey.Exp(g, sk, p)

	return par
}
