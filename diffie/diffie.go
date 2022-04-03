package diffie

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
)

// Diffie-Hellman algorithm demo.
func Demo(fail bool) {

	// Parameter generation

	p, err := rand.Prime(rand.Reader, 128)
	common.CheckErr(err)

	fmt.Printf("p = 0x%x\n", p)

	// Get p - 1
	tmp := big.NewInt(0).Sub(p, big.NewInt(1))

	g, err := rand.Int(rand.Reader, tmp)
	common.CheckErr(err)

	fmt.Printf("g = 0x%x\n\n", g)

	// Create participants

	parA := CreateParticipant(g, p)
	parB := CreateParticipant(g, p)

	fmt.Printf("Participant A:\n\tsk = 0x%x\n\tpk = 0x%x\n", parA.SecretKey, parA.PublicKey)
	fmt.Printf("Participant B:\n\tsk = 0x%x\n\tpk = 0x%x\n\n", parB.SecretKey, parB.PublicKey)

	// Generate session keys

	parA.GenerateSessionKey(parB.PublicKey)

	if fail {
		parB.SecretKey, err = rand.Int(rand.Reader, new(big.Int).Sub(g, big.NewInt(500)))
		if err != nil {
			log.Fatal(err)
		}
	}

	parB.GenerateSessionKey(parA.PublicKey)

	fmt.Printf("Participant A's session key: 0x%v\n", parA.SessionKey)
	fmt.Printf("Participant B's session key: 0x%v\n", parB.SessionKey)
}
