package main

import (
	"log"
	"net/http"
	"time"

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

	server := &http.Server{
		Addr:              ":8000",
		ReadHeaderTimeout: 3 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
