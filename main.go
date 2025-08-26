package main

import (
	"log"

	"github.com/storacha/delegator/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
