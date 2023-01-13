package main

import (
	"log"

	"github.com/rest-go/auth"
)

func main() {
	if err := auth.Setup(); err != nil {
		log.Fatal(err)
	}
}
