// Package source defines the multi-source trust adapter contract for the
// trust-anchor service.
//
// The EU LOTL and the national trusted lists are ingested through Source
// implementations in package `ingest` (fetch → verify → extract, one adapter
// per source type), so a new list-shaped source is a new adapter rather than
// a new branch through the pipeline. Registry-shaped sources (RegistrySource)
// and the remaining declared sources are not yet migrated; their contracts
// are pinned here.
package source

import (
	"context"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Type is the source-type discriminator. It becomes a first-class
// column/field on every source so new sources are new adapters, not new
// branches through the pipeline.
type Type string

const (
	// TS 119 612-shaped sources — reuse the XMLDSig + pinned-signer pipeline.
	TypeEULOTL            Type = "eu-lotl"
	TypeNationalTL        Type = "national-tl"
	TypeWalletProviderTL  Type = "wallet-provider-list"
	TypeCertifiedWalletTL Type = "certified-wallet-list" // CIR 2025/849
	TypeQTSPTL            Type = "qtsp-tl"
	// Registry-shaped — NOT a CA bundle; see RegistrySource.
	TypeRPRegistry Type = "rp-registry" // CIR 2025/848
)

// Raw is the fetched source payload plus the change-detection metadata:
// Digest is the published sibling ".sha2" (SHA-256 hex), Sequence is the
// list's TSLSequenceNumber when applicable. The manager uses these to skip
// unchanged sources before Verify.
type Raw struct {
	Bytes    []byte
	Digest   string
	Sequence uint64
}

// Source is the per-source-type adapter contract. The common, TS 119 612-shaped
// implementation (LOTL, national/wallet/QTSP lists) verifies XMLDSig against
// pinned signers and extracts trust anchors. Registry-shaped sources implement
// RegistrySource instead (different verification + projection).
type Source interface {
	// Type returns the source-type discriminator.
	Type() Type
	// ID is the stable per-source identity (territory code, list id, …).
	ID() string

	// Fetch retrieves the current payload + change-detection metadata. It SHOULD
	// consult the sibling digest first and return ErrUnchanged when the digest
	// matches the last seen value within NextUpdate (the manager then skips
	// Verify/Extract).
	Fetch(ctx context.Context, last *Raw) (*Raw, error)

	// Verify authenticates raw (XMLDSig vs the pinned signer set) and returns the
	// verified bytes. This is the ONLY trust gate; Fetch and the digest are never
	// trust inputs.
	Verify(ctx context.Context, raw *Raw, pinnedSignersDER [][]byte) ([]byte, error)

	// Extract parses verified bytes into trust anchors (the TS 119 612-shaped
	// projection).
	Extract(verified []byte) ([]trust.Anchor, error)
}

// RegistrySource is the contract for registry-shaped sources (rp-registry):
// instead of trust anchors they project to entitlement records (which relying
// party may request which attributes), served under a different API surface
// (/v1/rp/*). Verification follows the registry's published format, not
// necessarily TS 119 612 XMLDSig.
//
// The concrete entitlement record type is intentionally left undefined in this
// scaffold — it is specified against CIR 2025/848 + the ARF annex when that
// work is scheduled.
type RegistrySource interface {
	Type() Type
	ID() string
	Fetch(ctx context.Context, last *Raw) (*Raw, error)
	Verify(ctx context.Context, raw *Raw, pinnedSignersDER [][]byte) ([]byte, error)
	// ExtractEntitlements parses verified bytes into the registry projection.
	// Return type is not yet defined.
	// ExtractEntitlements(verified []byte) ([]Entitlement, error)
}

// ErrUnchanged is returned by Fetch when the sibling digest matches the last
// seen value and the source is within NextUpdate — the manager skips
// Verify/Extract and carries the previous projection forward.
var ErrUnchanged = errUnchanged{}

type errUnchanged struct{}

func (errUnchanged) Error() string { return "source: unchanged since last fetch" }
