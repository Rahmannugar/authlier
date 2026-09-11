// Package mysql provides Authlier storage backed by MySQL.
package mysql

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/internal/migrate"
	driver "github.com/go-sql-driver/mysql"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var ErrInvalidConfig = errors.New("invalid MySQL adapter configuration")

type SecretCodec interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type Config struct {
	Secrets SecretCodec
}

type Adapter struct {
	database *sql.DB
	secrets  SecretCodec
}

func New(database *sql.DB, config Config) (*Adapter, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalidConfig)
	}
	return &Adapter{database: database, secrets: config.Secrets}, nil
}

func (adapter *Adapter) Stores() authlier.Stores {
	return authlier.Stores{
		EmailPassword:     adapter.EmailPassword(),
		EmailVerification: adapter.EmailVerification(),
		Google:            adapter.Google(),
		OIDC:              adapter.OIDC(),
		Passkeys:          adapter.Passkeys(),
		PasswordReset:     adapter.PasswordReset(),
		RefreshTokens:     adapter.RefreshTokens(),
		SAML:              adapter.SAML(),
		Sessions:          adapter.Sessions(),
		TOTP:              adapter.TOTP(),
		AccessSessions:    adapter.AccessSessions(),
	}
}

func (adapter *Adapter) Migrate(ctx context.Context) error {
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("open migrations: %w", err)
	}
	files, err := migrate.Read(migrations)
	if err != nil {
		return err
	}
	for _, file := range files {
		tx, err := adapter.database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", file.Version, err)
		}
		if err := applyMigration(ctx, tx, file); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", file.Version, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, tx *sql.Tx, file migrate.Migration) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS authlier_schema_migrations (
		version varchar(255) PRIMARY KEY,
		applied_at datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM authlier_schema_migrations WHERE version = ?)",
		file.Version,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check migration %s: %w", file.Version, err)
	}
	if exists {
		return nil
	}
	for _, statement := range file.SQL {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %s: %w", file.Version, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO authlier_schema_migrations (version) VALUES (?)", file.Version,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", file.Version, err)
	}
	return nil
}

func uniqueViolation(err error) bool {
	var mysqlError *driver.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

var _ authlier.Database = (*Adapter)(nil)
