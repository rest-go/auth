package auth

import (
	"context"
	"log"
	"net/http"
	"os"
	"testing"

	j "github.com/rest-go/rest/pkg/jsonutil"
	"github.com/rest-go/rest/pkg/sqlx"
)

var testAuth Auth

func TestMain(m *testing.M) {
	db, err := sqlx.Open("sqlite://ci.db")
	if err != nil {
		log.Fatal(err)
	}
	testAuth = Auth{db: db}

	// drop previous test tables
	_, err = testAuth.db.ExecQuery(context.Background(), "DROP TABLE IF EXISTS users")
	if err != nil {
		log.Fatal(err)
	}
	_, err = testAuth.db.ExecQuery(context.Background(), "DROP TABLE IF EXISTS policies")
	if err != nil {
		log.Fatal(err)
	}

	// setup auth tables
	val := testAuth.setup()
	if res, ok := val.(*j.Response); ok {
		if res.Code != http.StatusOK {
			log.Fatal(res.Msg)
		}
	}

	os.Exit(m.Run())
}