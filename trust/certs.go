package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parseCerts reads one or more certificates from PEM, falling back to DER.
func parseCerts(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) > 0 {
		return out, nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("neither PEM nor DER certificate: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}
