package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

const (
	ErrorRandom = "Unable to generate random number"
	ErrorPrime  = "Unable to generate prime"
)

type Participant struct {
	PublicKey  *big.Int
	secretKey  *big.Int
	SessionKey *big.Int
}

func (par *Participant) GenerateSessionKey(publicKey, p *big.Int) {
	par.SessionKey = new(big.Int)
	par.SessionKey.Exp(publicKey, par.secretKey, p)
}

func CreateParticipant(g, p *big.Int) *Participant {
	par := new(Participant)

	sk, err := rand.Int(rand.Reader, p)
	checkErr(err, ErrorPrime)

	par.secretKey = sk
	par.PublicKey = new(big.Int)
	par.PublicKey.Exp(g, sk, p)

	return par
}

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

	fmt.Printf("Participant A:\n\tsk = 0x%x\n\tpk = 0x%x\n", parA.secretKey, parA.PublicKey)
	fmt.Printf("Participant B:\n\tsk = 0x%x\n\tpk = 0x%x\n\n", parB.secretKey, parB.PublicKey)

	parA.GenerateSessionKey(parB.PublicKey, p)
	parB.GenerateSessionKey(parA.PublicKey, p)

	fmt.Printf("Participant A's session key: 0x%v\n", parA.SessionKey)
	fmt.Printf("Participant B's session key: 0x%v\n", parB.SessionKey)
}
