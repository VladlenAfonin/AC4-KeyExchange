package common

import "log"

// Checks if err is nil and prints the message exiting the program if true.
func CheckErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
