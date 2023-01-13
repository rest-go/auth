package orm

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/rest-go/rest/pkg/database"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var dialectors = map[string]func(*sql.DB) gorm.Dialector{
	"postgres": func(db *sql.DB) gorm.Dialector {
		return postgres.New(postgres.Config{
			Conn: db,
		})
	},
	"mysql": func(db *sql.DB) gorm.Dialector {
		return mysql.New(mysql.Config{
			Conn: db,
		})
	},
}

func Open(url string) (*gorm.DB, error) {
	sqlDB, err := database.Open(url)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(url, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid db url: %s", url)
	}
	driver := parts[0]
	path := parts[1]
	if driver == "sqlite" {
		return gorm.Open(sqlite.Open(path), &gorm.Config{})
	}

	return gorm.Open(dialectors[driver](sqlDB), &gorm.Config{})
}
