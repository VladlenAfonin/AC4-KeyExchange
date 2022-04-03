package sts

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"

	"github.com/VladlenAfonin/AC4-KeyExchange/common"
)

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

	fmt.Printf("Participant A:\n\tsk = 0x%x\n\tpk = %x\n", parA.PrivateKey.D, parA.PublicKey)
	fmt.Printf("Participant B:\n\tsk = 0x%x\n\tpk = %x\n\n", parB.PrivateKey.D, parB.PublicKey)

	// 1.

	ax := parA.GenX()

	// 2.

	ay, signB := parB.GenX2(ax)

	// 3.

	signA, err := parA.Check(ay, signB, parB.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// 4.

	// Fail condition
	if fail {
		tmp, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			log.Fatal(err)
		}

		parA.PublicKey = &tmp.PublicKey
	}

	if err = parB.Check2(ax, signA, parA.PublicKey); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Participant A's session key: 0x%x\n", parA.SessionKey)
	fmt.Printf("Participant B's session key: 0x%x\n", parB.SessionKey)
}
