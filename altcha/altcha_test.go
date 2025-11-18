package altcha

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateChallenge(t *testing.T) {
	opts := ChallengeOptions{
		Algorithm:  "SHA-256",
		MaxNumber:  100000,
		HMACKey:    "test-key-minimum-32-characters-long",
		SaltLength: 12,
	}

	challenge, err := CreateChallenge(opts)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	// Validate challenge structure
	if challenge.Algorithm != "SHA-256" {
		t.Errorf("Expected algorithm SHA-256, got %s", challenge.Algorithm)
	}
	if challenge.Challenge == "" {
		t.Error("Challenge should not be empty")
	}
	if challenge.Salt == "" {
		t.Error("Salt should not be empty")
	}
	if challenge.Signature == "" {
		t.Error("Signature should not be empty")
	}
	if challenge.MaxNumber != 100000 {
		t.Errorf("Expected MaxNumber 100000, got %d", challenge.MaxNumber)
	}
}

func TestCreateChallenge_Algorithms(t *testing.T) {
	algorithms := []string{"SHA-256", "SHA-384", "SHA-512"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			opts := ChallengeOptions{
				Algorithm:  algo,
				MaxNumber:  100000,
				HMACKey:    "test-key-minimum-32-characters-long",
				SaltLength: 12,
			}

			challenge, err := CreateChallenge(opts)
			if err != nil {
				t.Fatalf("CreateChallenge failed for %s: %v", algo, err)
			}

			if challenge.Algorithm != algo {
				t.Errorf("Expected algorithm %s, got %s", algo, challenge.Algorithm)
			}
		})
	}
}

func TestCreateChallenge_InvalidAlgorithm(t *testing.T) {
	opts := ChallengeOptions{
		Algorithm:  "MD5",
		MaxNumber:  100000,
		HMACKey:    "test-key-minimum-32-characters-long",
		SaltLength: 12,
	}

	_, err := CreateChallenge(opts)
	if err == nil {
		t.Error("Expected error for unsupported algorithm MD5")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("Expected unsupported algorithm error, got: %v", err)
	}
}

func TestCreateChallenge_MissingHMACKey(t *testing.T) {
	opts := ChallengeOptions{
		Algorithm:  "SHA-256",
		MaxNumber:  100000,
		HMACKey:    "",
		SaltLength: 12,
	}

	_, err := CreateChallenge(opts)
	if err == nil {
		t.Error("Expected error for missing HMACKey")
	}
}

func TestCreateChallenge_Defaults(t *testing.T) {
	opts := ChallengeOptions{
		HMACKey:   "test-key-minimum-32-characters-long",
		Algorithm: "SHA-256",
		MaxNumber: 100000,
	}

	challenge, err := CreateChallenge(opts)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	// Check challenge is valid
	if challenge.Algorithm != "SHA-256" {
		t.Errorf("Expected algorithm SHA-256, got %s", challenge.Algorithm)
	}
	if challenge.MaxNumber != 100000 {
		t.Errorf("Expected MaxNumber 100000, got %d", challenge.MaxNumber)
	}
}

func TestVerifySolution(t *testing.T) {
	hmacKey := "test-key-minimum-32-characters-long"

	// Create a challenge first
	opts := ChallengeOptions{
		Algorithm:  "SHA-256",
		MaxNumber:  1000,
		HMACKey:    hmacKey,
		SaltLength: 12,
	}

	challenge, err := CreateChallenge(opts)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	// Create solution payload (base64 encoded JSON)
	solution := Solution{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
		Number:    0, // Would be solved by client in real scenario
	}

	payloadJSON, err := json.Marshal(solution)
	if err != nil {
		t.Fatalf("Failed to marshal solution: %v", err)
	}

	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	// Verify solution (will fail because we didn't actually solve it)
	// This tests the verification logic, not the solution correctness
	valid, err := VerifySolution(payload, hmacKey, false)
	if err != nil {
		t.Fatalf("VerifySolution failed: %v", err)
	}

	// Should be invalid because number 0 is unlikely to be the solution
	if valid {
		t.Error("Expected invalid solution for unsolv'd challenge")
	}
}

func TestVerifySolution_InvalidPayload(t *testing.T) {
	hmacKey := "test-key-minimum-32-characters-long"

	// Test with invalid base64
	_, err := VerifySolution("invalid-base64!@#", hmacKey, false)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test with valid base64 but invalid JSON
	invalidPayload := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err = VerifySolution(invalidPayload, hmacKey, false)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestVerifySolution_WrongSignature(t *testing.T) {
	hmacKey := "test-key-minimum-32-characters-long"

	solution := Solution{
		Algorithm: "SHA-256",
		Challenge: "test-challenge",
		Salt:      "test-salt",
		Signature: "wrong-signature",
		Number:    0,
	}

	payloadJSON, _ := json.Marshal(solution)
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	valid, err := VerifySolution(payload, hmacKey, false)
	if err != nil {
		t.Fatalf("VerifySolution failed: %v", err)
	}

	if valid {
		t.Error("Expected invalid solution for wrong signature")
	}
}

func BenchmarkCreateChallenge(b *testing.B) {
	opts := ChallengeOptions{
		Algorithm:  "SHA-256",
		MaxNumber:  100000,
		HMACKey:    "test-key-minimum-32-characters-long",
		SaltLength: 12,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateChallenge(opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySolution(b *testing.B) {
	hmacKey := "test-key-minimum-32-characters-long"

	solution := Solution{
		Algorithm: "SHA-256",
		Challenge: "test-challenge",
		Salt:      "test-salt",
		Signature: "test-signature",
		Number:    0,
	}

	payloadJSON, _ := json.Marshal(solution)
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifySolution(payload, hmacKey, false)
	}
}
