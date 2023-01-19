package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var policies = map[string]map[string]string{
	// Default policies
	// users are limited to by `id` field
	"users": {
		"all": "id = auth_user.id",
	},
	// policies operations are limited to admin user
	"policies": {
		"all": "auth_user.is_admin",
	},
	// all tables are limited to filter by user_id by default
	"all": {
		"all": "user_id = auth_user.id",
	},

	// Custom policies
	// todos operations are limited by `author_id` field
	"todos": {
		"all": "author_id = auth_user.id",
	},
	"articles": {
		"read": "",
		"all":  "author_id = auth_user.id",
	},
}

func TestUser_HasPerm(t *testing.T) {
	for _, test := range []struct {
		name             string
		user             User
		table            string
		action           Action
		hasPerm          bool
		withUserIDColumn string
	}{
		{
			name:             "users has permission to read their records",
			user:             User{IsAdmin: false},
			table:            "users",
			action:           ActionRead,
			hasPerm:          true,
			withUserIDColumn: "id",
		},
		{
			name:             "non-admin users don't have permission on policies",
			user:             User{IsAdmin: false},
			table:            "policies",
			action:           ActionRead,
			hasPerm:          false,
			withUserIDColumn: "",
		},
		{
			name:             "admin users have permission on policies",
			user:             User{IsAdmin: true},
			table:            "policies",
			action:           ActionRead,
			hasPerm:          true,
			withUserIDColumn: "",
		},
		{
			name:             "limit by `user_id` field by default",
			user:             User{IsAdmin: false},
			table:            "comments",
			action:           ActionRead,
			hasPerm:          true,
			withUserIDColumn: "user_id",
		},
		{
			name:             "users have read permission on todos with custom column",
			user:             User{IsAdmin: false},
			table:            "todos",
			action:           ActionRead,
			hasPerm:          true,
			withUserIDColumn: "author_id",
		},
		{
			name:             "users have write permission on todos with custom column",
			user:             User{IsAdmin: false},
			table:            "todos",
			action:           ActionCreate,
			hasPerm:          true,
			withUserIDColumn: "author_id",
		},
		{
			name:             "users have permission on read articles",
			user:             User{IsAdmin: false},
			table:            "articles",
			action:           ActionRead,
			hasPerm:          true,
			withUserIDColumn: "",
		},
		{
			name:             "limit to current auth user when read mine",
			user:             User{IsAdmin: false},
			table:            "articles",
			action:           ActionReadMine,
			hasPerm:          true,
			withUserIDColumn: "author_id",
		},
	} {
		t.Log(test.name)
		hasPerm, userIDColumn := test.user.HasPerm(test.table, test.action, policies)
		assert.Equal(t, test.hasPerm, hasPerm)
		assert.Equal(t, test.withUserIDColumn, userIDColumn)
	}
}
