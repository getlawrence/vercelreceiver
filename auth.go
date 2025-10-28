package vercelreceiver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

const xVercelSignatureHeader = "x-vercel-signature"

// verifySignature validates the x-vercel-signature header against the secret
func verifySignature(secret, bodyBytes []byte, signature string) bool {
	if len(secret) == 0 {
		// If no secret is configured, skip verification
		return true
	}

	if signature == "" {
		return false
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, secret)
	mac.Write(bodyBytes)
	expectedMAC := mac.Sum(nil)
	expectedSignature := hex.EncodeToString(expectedMAC)

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// verifyRequest validates the HTTP request signature
func verifyRequest(r *http.Request, secret string, bodyBytes []byte) error {
	if secret == "" {
		// No secret configured, skip verification
		return nil
	}

	signature := r.Header.Get(xVercelSignatureHeader)
	if signature == "" {
		return fmt.Errorf("missing %s header", xVercelSignatureHeader)
	}

	if !verifySignature([]byte(secret), bodyBytes, signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
