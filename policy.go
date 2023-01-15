package auth

const (
	createPolicyTable = `
	CREATE TABLE policies (
		id %s,
		table_name VARCHAR(128)
		action VARCHAR(16),
		column VARCHAR(128),
		operator VARCHAR(8),
		expression VARCHAR(128)
		internal BOOLEAN
	)
	`
	createInternalPolicy = `INSERT INTO policies (table_name, action, column, operator, expression, internal) VALUES (?, ?, ?, ?, ?, true)`
	createPolicy         = `INSERT INTO policies (table_name, action, column, operator, expression) VALUES (?, ?, ?, ?, ?)`
)

// Policy represents a security policy against a table
type Policy struct {
	ID         int64  `json:"id"`
	TableName  string `json:"table_name"`
	Action     string `json:"action"`
	Column     bool   `json:"column"`
	Operator   bool   `json:"operator"`
	Expression bool   `json:"expression"`
}
