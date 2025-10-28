// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySignature(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte("test-body")

	testCases := []struct {
		name      string
		secret    []byte
		body      []byte
		signature string
		expected  bool
	}{
		{
			name:      "valid signature",
			secret:    secret,
			body:      body,
			signature: createTestSignature(secret, body),
			expected:  true,
		},
		{
			name:      "invalid signature",
			secret:    secret,
			body:      body,
			signature: "invalid-signature",
			expected:  false,
		},
		{
			name:      "missing signature",
			secret:    secret,
			body:      body,
			signature: "",
			expected:  false,
		},
		{
			name:      "no secret configured",
			secret:    nil,
			body:      body,
			signature: "",
			expected:  true, // Should pass when no secret
		},
		{
			name:      "empty secret",
			secret:    []byte(""),
			body:      body,
			signature: "",
			expected:  true, // Should pass with empty secret
		},
		{
			name:      "wrong signature",
			secret:    secret,
			body:      body,
			signature: createTestSignature([]byte("wrong-secret"), body),
			expected:  false,
		},
		{
			name:      "different body",
			secret:    secret,
			body:      []byte("different-body"),
			signature: createTestSignature(secret, []byte("test-body")),
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := verifySignature(tc.secret, tc.body, tc.signature)
			assert.Equal(t, tc.expected, result, "Signature verification result mismatch")
		})
	}
}

func TestVerifyRequest(t *testing.T) {
	testCases := []struct {
		name         string
		secret       string
		signature    string
		body         []byte
		expectedErr  bool
		errorMessage string
	}{
		{
			name:        "valid signature",
			secret:      "test-secret",
			signature:   createTestSignature([]byte("test-secret"), []byte("test-body")),
			body:        []byte("test-body"),
			expectedErr: false,
		},
		{
			name:         "invalid signature",
			secret:       "test-secret",
			signature:    "invalid-signature",
			body:         []byte("test-body"),
			expectedErr:  true,
			errorMessage: "invalid signature",
		},
		{
			name:         "missing signature header",
			secret:       "test-secret",
			signature:    "",
			body:         []byte("test-body"),
			expectedErr:  true,
			errorMessage: "missing x-vercel-signature header",
		},
		{
			name:        "no secret configured",
			secret:      "",
			signature:   "",
			body:        []byte("test-body"),
			expectedErr: false,
		},
		{
			name:        "empty secret skips verification",
			secret:      "",
			signature:   "",
			body:        []byte("test-body"),
			expectedErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost/test", nil)

			if tc.signature != "" || tc.secret != "" {
				req.Header.Set(xVercelSignatureHeader, tc.signature)
			}

			err := verifyRequest(req, tc.secret, tc.body)

			if tc.expectedErr {
				require.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSignatureHeaderName(t *testing.T) {
	// Test that the header name constant is correct
	assert.Equal(t, "x-vercel-signature", xVercelSignatureHeader)
}

func createTestSignature(secret []byte, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
