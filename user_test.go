package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var policies = map[string]map[string]Policy{
	// default policies
	"users": {
		"all": {
			Description: "users are limited to by `id` field",
			TableName:   "users",
			Action:      "all",
			Expression:  "id = auth_user.id",
		},
	},
	"policies": {
		"all": {
			Description: "policies operations are limited to admin user",
			TableName:   "policies",
			Action:      "all",
			Expression:  "auth_user.is_admin",
		},
	},
	"all": {
		"all": {
			Description: "all tables are limited to filter by user_id by default",
			TableName:   "all",
			Action:      "all",
			Expression:  "user_id = auth_user.id",
		},
	},

	// custom policies
	"todos": {
		"all": {
			Description: "todos operations are limited by `author_id` field",
			TableName:   "todos",
			Action:      "all",
			Expression:  "author_id = auth_user.id",
		},
	},
	"articles": {
		"read": {
			Description: "read is allowed",
			TableName:   "articles",
			Action:      "read",
			Expression:  "",
		},
		"all": {
			Description: "read_mine/update/delete are limited is limited",
			TableName:   "articles",
			Action:      "all",
			Expression:  "author_id = auth_user.id",
		},
	},
}

func TestUser_HasPerm(t *testing.T) {
	for _, test := range []struct {
		name             string
		user             User
		table            string
		action           string
		hasPerm          bool
		withUserIDColumn string
	}{
		{
			name:             "users has permission to read their records",
			user:             User{IsAdmin: false},
			table:            "users",
			action:           "read",
			hasPerm:          true,
			withUserIDColumn: "id",
		},
		{
			name:             "non-admin users don't have permission on policies",
			user:             User{IsAdmin: false},
			table:            "policies",
			action:           "read",
			hasPerm:          false,
			withUserIDColumn: "",
		},
		{
			name:             "admin users have permission on policies",
			user:             User{IsAdmin: true},
			table:            "policies",
			action:           "read",
			hasPerm:          true,
			withUserIDColumn: "",
		},
		{
			name:             "limit by `user_id` field by default",
			user:             User{IsAdmin: false},
			table:            "comments",
			action:           "read",
			hasPerm:          true,
			withUserIDColumn: "user_id",
		},
		{
			name:             "users have read permission on todos with custom column",
			user:             User{IsAdmin: false},
			table:            "todos",
			action:           "read",
			hasPerm:          true,
			withUserIDColumn: "author_id",
		},
		{
			name:             "users have write permission on todos with custom column",
			user:             User{IsAdmin: false},
			table:            "todos",
			action:           "write",
			hasPerm:          true,
			withUserIDColumn: "author_id",
		},
		{
			name:             "users have permission on read articles",
			user:             User{IsAdmin: false},
			table:            "articles",
			action:           "read",
			hasPerm:          true,
			withUserIDColumn: "",
		},
		{
			name:             "limit to current auth user when read mine",
			user:             User{IsAdmin: false},
			table:            "articles",
			action:           "read_mine",
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
