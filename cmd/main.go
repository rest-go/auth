package main

import (
	"log"

	"github.com/rest-go/auth"
)

func main() {
	auth := auth.Auth{}
	if err := auth.Setup(); err != nil {
		log.Fatal(err)
	}
}
