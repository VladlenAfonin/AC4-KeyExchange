package diffie

import "log"

const (
	ErrorRandom  = "Unable to generate random number"
	ErrorPrime   = "Unable to generate prime"
	ErrorReading = "Unable to read from stream"
)

// Checks if err is nil and prints the message exiting the program if true.
func checkErr(err error, message string) {
	if err != nil {
		log.Fatal(message)
	}
}
