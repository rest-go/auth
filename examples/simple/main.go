package main

import (
	"log"
	"net/http"

	"github.com/rest-go/auth"
)

func handle(w http.ResponseWriter, req *http.Request) {
	user := auth.GetUser(req)
	if user.IsAnonymous() {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	dbURL := "sqlite://my.db"
	jwtSecret := "my secret"
	restAuth, err := auth.New(dbURL, []byte(jwtSecret))
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/auth/", restAuth)
	http.Handle("/", restAuth.Middleware(http.HandlerFunc(handle)))
	log.Fatal(http.ListenAndServe(":8000", nil)) //nolint:gosec
}
