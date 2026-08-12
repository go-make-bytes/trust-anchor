package tsl

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/beevik/etree"
	xmldsig "github.com/lafriks/go-xmldsig/v2"
)

const dsigNamespace = "http://www.w3.org/2000/09/xmldsig#"

// findEnvelopedSignature returns the enveloped ds:Signature element. Per the
// TS 119 612 profile it must be a direct child of TrustServiceStatusList, so
// we only scan the root's immediate children — this both enforces the profile
// requirement and rejects any nested signature that does not belong there.
//
// Unlike the old relocateSignatureFirst, this does not mutate the document.
// The located element is handed to xmldsig's ValidateSignature, which resolves
// it inside its own defensive copy and skips the library's signature search
// entirely. (go-xmldsig v2.3.0 also added a budget-free children-first search,
// so a plain Validate would now work on tens-of-thousands-of-element trusted
// lists too; passing the located element is strictly tighter — it keeps the
// direct-child profile check and avoids any traversal of untrusted input.)
func findEnvelopedSignature(root *etree.Element) (*etree.Element, error) {
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && resolveNamespace(child, child.Space) == dsigNamespace {
			return child, nil
		}
	}
	return nil, fmt.Errorf("tsl: no enveloped XML signature found as direct child of %s", root.Tag)
}

// resolveNamespace resolves an element's namespace prefix by walking the
// ancestor chain for xmlns declarations.
func resolveNamespace(el *etree.Element, prefix string) string {
	for e := el; e != nil; e = e.Parent() {
		for _, attr := range e.Attr {
			if prefix == "" && attr.Space == "" && attr.Key == "xmlns" {
				return attr.Value
			}
			if prefix != "" && attr.Space == "xmlns" && attr.Key == prefix {
				return attr.Value
			}
		}
	}
	return ""
}

// fixedClock pins the verification clock (pivot-chain processing).
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// Verify validates the enveloped XMLDSig signature of raw against the pinned
// signer certificates and returns the signature-verified document bytes.
//
// The returned bytes are the exclusive-C14N form of the verified document
// reference — downstream parsing must consume these, never raw, so that only
// signed content is trusted. Verification is pinned: the KeyInfo certificate
// must be byte-identical to one of signers (no chain building) and must be
// within its validity period. All SignedInfo references are digest-checked,
// including the XAdES SignedProperties reference.
func Verify(raw []byte, signers []*x509.Certificate) ([]byte, error) {
	return verify(raw, signers, nil)
}

// VerifyAt is Verify with the signer-certificate validity window checked at
// the given time instead of now. It exists for pivot-chain processing:
// historical pivots were signed by certificates that have since expired, and
// the correct check is validity at the pivot's issue time. Callers must take
// `at` from the document itself (pre-parsed ListIssueDateTime) and re-check
// the value against the verified content afterwards.
func VerifyAt(raw []byte, signers []*x509.Certificate, at time.Time) ([]byte, error) {
	return verify(raw, signers, &at)
}

// VerifyAndParse verifies raw against the pinned signers and parses the
// verified content. This is the only entry point production ingestion uses.
func VerifyAndParse(raw []byte, signers []*x509.Certificate) (*TrustedList, error) {
	verified, err := Verify(raw, signers)
	if err != nil {
		return nil, err
	}
	return Parse(verified)
}

func verify(raw []byte, signers []*x509.Certificate, at *time.Time) ([]byte, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("tsl: no expected signer certificates configured")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("tsl: parse XML for signature verification: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("tsl: document has no root element")
	}
	sig, err := findEnvelopedSignature(root)
	if err != nil {
		return nil, err
	}

	ctx := xmldsig.NewDefaultValidationContext(&xmldsig.MemoryX509CertificateStore{Roots: signers})
	// TSL/XAdES reference IDs use the `Id` attribute (the library default is
	// `ID`), e.g. the SignedProperties reference target.
	ctx.IDAttribute = "Id"
	if at != nil {
		ctx.Clock = fixedClock{*at}
	}

	// ValidateSignature (go-xmldsig v2.3.0) validates the signature element we
	// located, skipping the library's own search; root is defensively copied
	// internally, so neither argument is mutated.
	validated, err := ctx.ValidateSignature(root, sig)
	if err != nil {
		return nil, fmt.Errorf("tsl: XML signature verification failed: %w", err)
	}

	// Validate returns one element per digest-checked reference; pick the
	// document reference (the TrustServiceStatusList root).
	var verifiedRoot *etree.Element
	for _, el := range validated {
		if el.Tag == root.Tag {
			verifiedRoot = el
			break
		}
	}
	if verifiedRoot == nil {
		return nil, fmt.Errorf("tsl: signature does not cover the %s document root", root.Tag)
	}

	// Serialize the verified element in its canonical form — the exact byte
	// stream the signed digest covered.
	b, err := xmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(verifiedRoot)
	if err != nil {
		return nil, fmt.Errorf("tsl: serialize verified document: %w", err)
	}
	return b, nil
}
