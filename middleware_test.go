package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	j "github.com/rest-go/rest/pkg/jsonutil"
	"github.com/stretchr/testify/assert"
)

func testHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	if user.IsAnonymous() {
		j.Write(w, &j.Response{Code: http.StatusUnauthorized})
		return
	}
	if !user.IsAuthenticated() {
		j.Write(w, &j.Response{Code: http.StatusUnauthorized})
		return
	}
	j.Write(w, user)
}

func TestAuthMiddleware(t *testing.T) {
	auth, err := New("sqlite://ci.db", []byte("test"))
	assert.Nil(t, err)
	_, err = auth.db.ExecQuery(context.Background(), "DROP TABLE IF EXISTS users")
	assert.Nil(t, err)
	_ = auth.setup()

	body := strings.NewReader(`{
			"username": "hello",
			"password": "world"
		}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, req)

	body = strings.NewReader(`{
		"username": "hello",
		"password": "world"
	}`)
	req = httptest.NewRequest(http.MethodPost, "/auth/login", body)
	w = httptest.NewRecorder()
	auth.ServeHTTP(w, req)
	res := w.Result()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	var resData map[string]string
	err = json.Unmarshal(data, &resData)
	assert.Nil(t, err)
	token := resData["token"]

	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Add(AuthTokenHeader, token)
	w = httptest.NewRecorder()
	testHandler(w, req)
	res = w.Result()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Add(AuthTokenHeader, token)
	authHandler := auth.Middleware(http.HandlerFunc(testHandler))
	authHandler.ServeHTTP(w, req)
	res = w.Result()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	defer res.Body.Close()
	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	t.Log("get user data middleware: ", string(data))
	var userRes map[string]any
	err = json.Unmarshal(data, &userRes)
	assert.Nil(t, err)
}
