package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser_HasPerm(t *testing.T) {
	policies := map[string]map[string]Policy{
		"users": {
			"read": {
				Description: "read users is limited to current auth user or admin user",
				TableName:   "users",
				Action:      "read",
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
		"todos": {
			"read": {
				Description: "todos read is limited to current auth user",
				TableName:   "todos",
				Action:      "read",
				Expression:  "author_id = auth_user.id",
			},
		},
	}

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
			name:             "users have permission on todos with custom column",
			user:             User{IsAdmin: false},
			table:            "todos",
			action:           "read",
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
