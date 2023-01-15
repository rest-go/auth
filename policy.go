package auth

import (
	"context"
	"fmt"
	"log"

	"github.com/rest-go/rest/pkg/sqlx"
)

const (
	createPolicyTable = `
	CREATE TABLE policies (
		id %s,
		description VARCHAR(256) NOT NULL,
		table_name VARCHAR(128) NOT NULL,
		action VARCHAR(16) NOT NULL,
		expression VARCHAR(128) NOT NULL,
		internal BOOLEAN NOT NULL
	)
	`
	createPolicy = `
		INSERT INTO policies (description, table_name, action, expression, internal)
		VALUES (?, ?, ?, ?, true)
	`
)

var defaultPolicies = []Policy{
	{
		Description: "read users is limited to current auth user or admin user",
		TableName:   "users",
		Action:      "read",
		Expression:  "id == auth_user.id OR auth_user.is_admin",
	},
	{
		Description: "update users is limited to current auth user",
		TableName:   "users",
		Action:      "update",
		Expression:  "id == auth_user.id",
	},
	{
		Description: "delete users is limited to current auth user",
		TableName:   "users",
		Action:      "delete",
		Expression:  "id == auth_user.id",
	},
	{
		Description: "policies operations are limited to admin user",
		TableName:   "policies",
		Action:      "all",
		Expression:  "auth_user.is_admin AND NOT internal",
	},
}

// Policy represents a security policy against a table
type Policy struct {
	ID          int64  `json:"id"`
	Description string `json:"description"`
	TableName   string `json:"table_name"`
	Action      string `json:"action"`
	Column      string `json:"column"`
	Operator    string `json:"operator"`
	Expression  string `json:"expression"`
}

// setupPolicies create `policies` table and create a default internal policies
func setupPolicies(db *sqlx.DB) error {
	log.Print("create policies table")
	idSQL := primaryKeySQL[db.DriverName]
	createTableQuery := fmt.Sprintf(createPolicyTable, idSQL)
	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()
	_, dbErr := db.ExecQuery(ctx, createTableQuery)
	if dbErr != nil {
		return dbErr
	}

	log.Print("create default policies")
	for _, policy := range defaultPolicies {
		_, dbErr := db.ExecQuery(
			ctx,
			createPolicy,
			policy.Description,
			policy.TableName,
			policy.Action,
			policy.Expression,
		)
		if dbErr != nil {
			return dbErr
		}
	}
	return nil
}
