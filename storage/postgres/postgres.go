// Package postgres provides Authlier storage backed by PostgreSQL.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var ErrInvalidConfig = errors.New("invalid PostgreSQL adapter configuration")

type SecretCodec interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type Config struct {
	Secrets SecretCodec
}

type Adapter struct {
	pool    *pgxpool.Pool
	secrets SecretCodec
}

func New(pool *pgxpool.Pool, config Config) (*Adapter, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: pool is required", ErrInvalidConfig)
	}
	return &Adapter{pool: pool, secrets: config.Secrets}, nil
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
		tx, err := adapter.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", file.Version, err)
		}
		if err := applyMigration(ctx, tx, file); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", file.Version, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, tx pgx.Tx, file migrate.Migration) error {
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS authlier_schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM authlier_schema_migrations WHERE version = $1)",
		file.Version,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check migration %s: %w", file.Version, err)
	}
	if exists {
		return nil
	}
	for _, statement := range file.SQL {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %s: %w", file.Version, err)
		}
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO authlier_schema_migrations (version) VALUES ($1)", file.Version,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", file.Version, err)
	}
	return nil
}

var _ authlier.Database = (*Adapter)(nil)
