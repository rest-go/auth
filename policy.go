package auth

import (
	"context"
	"fmt"
	"log"

	"github.com/rest-go/rest/pkg/sqlx"
)

const (
	PolicyTableName   = "auth_policies"
	createPolicyTable = `
	CREATE TABLE auth_policies (
		id %s,
		description VARCHAR(256) NOT NULL,
		table_name VARCHAR(128) NOT NULL,
		action VARCHAR(16) NOT NULL,
		expression VARCHAR(128) NOT NULL,
		internal BOOLEAN NOT NULL
	)
	`
	createInternalPolicy = `
		INSERT INTO auth_policies (description, table_name, action, expression, internal)
		VALUES (?, ?, ?, ?, true)
	`
)

var defaultPolicies = []Policy{
	{
		Description: "policies operations are limited to admin user",
		TableName:   "auth_policies",
		Action:      "all",
		Expression:  "auth_user.is_admin",
	},
	{
		Description: "users are limited to filter by id by default",
		TableName:   "auth_users",
		Action:      "all",
		Expression:  "id = auth_user.id",
	},
	{
		Description: "all tables are limited to filter by user_id by default",
		TableName:   "all",
		Action:      "all",
		Expression:  "user_id = auth_user.id",
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
			createInternalPolicy,
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
