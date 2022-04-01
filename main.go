package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const (
	ErrorRandom  = "Unable to generate random number"
	ErrorPrime   = "Unable to generate prime"
	ErrorReading = "Unable to read from stream"
)

// Participant model.
type Participant struct {
	g *big.Int
	p *big.Int

	PublicKey  *big.Int
	secretKey  *big.Int
	SessionKey *big.Int
}

// Generates session key from another participant's public key.
func (par *Participant) GenerateSessionKey(publicKey *big.Int) {
	sessionKey := new(big.Int)
	sessionKey.Exp(publicKey, par.secretKey, par.p)

	hash := sha256.New
	hkdf := hkdf.New(hash, sessionKey.Bytes(), nil, nil)

	par.SessionKey = new(big.Int)
	buf := make([]byte, 16)

	_, err := io.ReadFull(hkdf, buf)
	checkErr(err, ErrorReading)

	par.SessionKey.SetBytes(buf)
}

// Initializes a new Participant.
func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)

	par.p = p
	par.g = g

	sk, err := rand.Int(rand.Reader, p)
	checkErr(err, ErrorPrime)

	par.secretKey = sk
	par.PublicKey = new(big.Int)
	par.PublicKey.Exp(g, sk, p)

	return par
}

// Checks if err is nil and prints the message extiting the program if true.
func checkErr(err error, message string) {
	if err != nil {
		log.Fatal(message)
	}
}

func main() {

	// Parameter generation

	p, err := rand.Prime(rand.Reader, 128)
	checkErr(err, ErrorPrime)

	fmt.Printf("p     = 0x%x\n", p)

	g, err := rand.Int(rand.Reader, p)
	checkErr(err, ErrorRandom)

	fmt.Printf("alpha = 0x%x\n\n", g)

	// Create participants

	parA := CreateParticipant(g, p)
	parB := CreateParticipant(g, p)

	fmt.Printf("Participant A:\n\tsk = 0x%x\n\tpk = 0x%x\n",
		parA.secretKey, parA.PublicKey)
	fmt.Printf("Participant B:\n\tsk = 0x%x\n\tpk = 0x%x\n\n",
		parB.secretKey, parB.PublicKey)

	// Generate session keys

	parA.GenerateSessionKey(parB.PublicKey)
	parB.GenerateSessionKey(parA.PublicKey)

	fmt.Printf("Participant A's session key: 0x%v\n", parA.SessionKey)
	fmt.Printf("Participant B's session key: 0x%v\n", parB.SessionKey)
}
