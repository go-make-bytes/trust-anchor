package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Postgres is the dual-mode DB-backed Store: versioned snapshot/bootstrap rows
// in the platform `trust_anchor` schema, reached ONLY through SECURITY DEFINER
// procedures under an EXECUTE-only role (authbyte-db/trust-anchor). The
// full serialized object is the source of truth; this package never issues raw
// table SQL — it only CALLs the procedures (mirrors authbyte-core/store).
//
// Selected when TRUST_STORE_DSN is set; FS/S3/memory remain the single-node default.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool to the platform PostgreSQL. The pool is
// lazy; connectivity is verified on first use.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: postgres connect: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// envelope is the structured result every procedure returns
// (util.result_success / util.result_error).
type envelope struct {
	Result  string          `json:"result"`
	Data    json.RawMessage `json:"data"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

// call invokes a SECURITY DEFINER procedure with the uniform JSONB envelope and
// returns the decoded `data` payload, or a typed error from result_error.
func (p *Postgres) call(ctx context.Context, proc string, in any) (json.RawMessage, error) {
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal input: %w", err)
	}

	// CALL with an INOUT parameter returns a single-column row carrying po_data;
	// NULL seeds the INOUT slot.
	q := fmt.Sprintf("CALL %s($1::jsonb, NULL::jsonb)", proc)

	var out []byte
	if err := p.pool.QueryRow(ctx, q, inJSON).Scan(&out); err != nil {
		// A procedure that fails after a write re-raises a structured error with
		// SQLSTATE P0001 (Pattern B) to force a rollback; its message is the
		// util.result_error JSON. Recover the code/message so callers see the
		// same shape as the validation (returned-error) path.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			var env envelope
			if json.Unmarshal([]byte(pgErr.Message), &env) == nil && env.Result == "error" {
				return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
			}
		}

		return nil, fmt.Errorf("store: %s: %w", proc, err)
	}

	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("store: %s: decode result: %w", proc, err)
	}
	if env.Result != "success" {
		return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
	}

	return env.Data, nil
}

// SaveSnapshot appends snap as a new version (trust_anchor.save_snapshot). The
// marshalled snapshot is the procedure input and is stored verbatim.
func (p *Postgres) SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error {
	_, err := p.call(ctx, "trust_anchor.save_snapshot", snap)

	return err
}

// LoadLatestSnapshot returns the newest snapshot, or (nil, nil) when none.
func (p *Postgres) LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error) {
	data, err := p.call(ctx, "trust_anchor.load_latest_snapshot", struct{}{})
	if err != nil {
		return nil, err
	}

	var res struct {
		Snapshot json.RawMessage `json:"snapshot"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: load snapshot: decode: %w", err)
	}
	if len(res.Snapshot) == 0 || string(res.Snapshot) == "null" {
		return nil, nil
	}

	var snap trust.Snapshot
	if err := json.Unmarshal(res.Snapshot, &snap); err != nil {
		return nil, fmt.Errorf("store: load snapshot: decode snapshot: %w", err)
	}

	return &snap, nil
}

// SaveBootstrap appends b as a new version (trust_anchor.save_bootstrap).
func (p *Postgres) SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error {
	_, err := p.call(ctx, "trust_anchor.save_bootstrap", b)

	return err
}

// LoadLatestBootstrap returns the authoritative bootstrap, or (nil, nil) when
// none.
func (p *Postgres) LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error) {
	data, err := p.call(ctx, "trust_anchor.load_latest_bootstrap", struct{}{})
	if err != nil {
		return nil, err
	}

	var res struct {
		Bootstrap json.RawMessage `json:"bootstrap"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: load bootstrap: decode: %w", err)
	}
	if len(res.Bootstrap) == 0 || string(res.Bootstrap) == "null" {
		return nil, nil
	}

	var b trust.Bootstrap
	if err := json.Unmarshal(res.Bootstrap, &b); err != nil {
		return nil, fmt.Errorf("store: load bootstrap: decode bootstrap: %w", err)
	}

	return &b, nil
}
