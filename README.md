# Auth

![ci](https://github.com/rest-go/auth/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/rest-go/auth/branch/main/graph/badge.svg?token=T38FWXMVY1)](https://codecov.io/gh/rest-go/auth)


Auth is a RESTFul authentication framework for Golang HTTP app.

It handles the common tasks of registration, logging in, logging out, JWT token generation, and JWT token verification. It makes it easy to plug in authentication to an application with a small amount of integration effort.


## Installation

``` bash
$ go get github.com/rest-go/auth
```

## Usage
import `auth` to your app, and add it to an HTTP route

``` go
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
```

## Setup database tables

Send a `POST` request to `/auth/setup` to set up database tables for users. This
will create a super user account and return the username and password in the
response.

``` bash
$ curl -XPOST "localhost:8000/auth/setup"
```

## Auth endpoints

By default, it provides the below endpoints for user management.

1. Register

``` bash
$ curl  -XPOST "localhost:8000/auth/register" -d '{"username":"hello", "password": "world"}'
```

2. Login

``` bash
$ curl  -XPOST "localhost:8000/auth/login" -d '{"username":"hello", "password": "world"}'
```

3. Logout

The authentication mechanism is based on JWT token, logout is a no-op on the
server side, and the client should clear the token by itself.
``` bash
$ curl  -XPOST "localhost:8000/auth/logout"
```

## Auth middleware and GetUser

Auth middleware will parse JWT token in the HTTP header, and when successful,
set the user in the request context, the `GetUser` method can be used to get the
user from request.

``` go
user := auth.GetUser(req)
```

