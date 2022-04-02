package diffie

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Diffie-Hellman algorithm demo.
func Demo() {

	// Parameter generation

	p, err := rand.Prime(rand.Reader, 128)
	checkErr(err, ErrorPrime)

	fmt.Printf("p     = 0x%x\n", p)

	// Get p - 1
	tmp := big.NewInt(0).Sub(p, big.NewInt(1))

	g, err := rand.Int(rand.Reader, tmp)
	checkErr(err, ErrorRandom)

	fmt.Printf("alpha = 0x%x\n\n", g)

	// Create participants

	parA := CreateParticipant(g, p)
	parB := CreateParticipant(g, p)

	fmt.Printf("Participant A:\n\tsk = 0x%x\n\tpk = 0x%x\n",
		parA.SecretKey, parA.PublicKey)
	fmt.Printf("Participant B:\n\tsk = 0x%x\n\tpk = 0x%x\n\n",
		parB.SecretKey, parB.PublicKey)

	// Generate session keys

	parA.GenerateSessionKey(parB.PublicKey)
	parB.GenerateSessionKey(parA.PublicKey)

	fmt.Printf("Participant A's session key: 0x%v\n", parA.SessionKey)
	fmt.Printf("Participant B's session key: 0x%v\n", parB.SessionKey)
}
