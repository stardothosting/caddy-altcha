package altcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

// ChallengeOptions contains options for creating a challenge
type ChallengeOptions struct {
	Algorithm  string
	MaxNumber  int
	SaltLength int
	HMACKey    string
	Expires    time.Time
}

// Challenge represents an ALTCHA challenge
type Challenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxNumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// Solution represents an ALTCHA solution
type Solution struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// CreateChallenge generates a new ALTCHA challenge
func CreateChallenge(opts ChallengeOptions) (*Challenge, error) {
	// Validate HMAC key
	if opts.HMACKey == "" {
		return nil, fmt.Errorf("HMAC key is required")
	}

	// Generate random salt
	salt, err := generateSalt(opts.SaltLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random number to solve for
	targetNum, err := generateRandomNumber(opts.MaxNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to generate target number: %w", err)
	}

	// Create challenge hash (NO separator between salt and number!)
	challengeData := fmt.Sprintf("%s%d", salt, targetNum)
	challengeHash, err := hashData(opts.Algorithm, challengeData)
	if err != nil {
		return nil, fmt.Errorf("failed to hash challenge: %w", err)
	}

	challenge := &Challenge{
		Algorithm: opts.Algorithm,
		Challenge: challengeHash,
		MaxNumber: opts.MaxNumber,
		Salt:      salt,
	}

	// Sign the challenge (HMAC of the challenge hash only)
	challenge.Signature, err = createHMAC(opts.HMACKey, challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	return challenge, nil
}

// VerifySolution verifies an ALTCHA solution payload
func VerifySolution(payload, hmacKey string, checkExpires bool) (bool, error) {
	// Decode base64 payload
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false, fmt.Errorf("invalid payload encoding: %w", err)
	}

	// Parse JSON
	var solution Solution
	if err := json.Unmarshal(decoded, &solution); err != nil {
		return false, fmt.Errorf("invalid payload format: %w", err)
	}

	// Verify signature by re-creating the challenge
	expectedSignature, err := createHMAC(hmacKey, solution.Challenge)
	if err != nil {
		return false, fmt.Errorf("failed to compute signature: %w", err)
	}

	if solution.Signature != expectedSignature {
		return false, nil
	}

	// Verify the solution (NO separator between salt and number!)
	solutionData := fmt.Sprintf("%s%d", solution.Salt, solution.Number)
	solutionHash, err := hashData(solution.Algorithm, solutionData)
	if err != nil {
		return false, fmt.Errorf("failed to hash solution: %w", err)
	}

	if solutionHash != solution.Challenge {
		return false, nil
	}

	return true, nil
}

// generateSalt creates a random salt
func generateSalt(length int) (string, error) {
	if length <= 0 {
		length = 12
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// generateRandomNumber creates a random number up to max
func generateRandomNumber(max int) (int, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return 0, err
	}

	// Convert to int and modulo
	num := int(bytes[0])<<24 | int(bytes[1])<<16 | int(bytes[2])<<8 | int(bytes[3])
	if num < 0 {
		num = -num
	}

	return num % max, nil
}

// hashData hashes data using the specified algorithm
func hashData(algorithm, data string) (string, error) {
	var h hash.Hash

	switch strings.ToUpper(algorithm) {
	case "SHA-256":
		h = sha256.New()
	case "SHA-384":
		h = sha512.New384()
	case "SHA-512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// createHMAC creates an HMAC signature
func createHMAC(key, data string) (string, error) {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParsePayload decodes and parses an ALTCHA payload
func ParsePayload(payload string) (*Solution, error) {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var solution Solution
	if err := json.Unmarshal(decoded, &solution); err != nil {
		return nil, fmt.Errorf("invalid payload format: %w", err)
	}

	return &solution, nil
}

// CreateSolutionPayload creates a solution payload (for testing)
func CreateSolutionPayload(algorithm, challenge, salt string, number int, hmacKey string) (string, error) {
	solution := Solution{
		Algorithm: algorithm,
		Challenge: challenge,
		Number:    number,
		Salt:      salt,
	}

	// Sign the solution (HMAC of challenge hash only)
	signature, err := createHMAC(hmacKey, solution.Challenge)
	if err != nil {
		return "", err
	}

	solution.Signature = signature

	// Encode as JSON then base64
	jsonData, err := json.Marshal(solution)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(jsonData), nil
}

// SolveChallenge finds a solution to a challenge (for testing)
func SolveChallenge(challenge *Challenge, hmacKey string, maxAttempts int) (string, error) {
	for i := 0; i < maxAttempts; i++ {
		testData := fmt.Sprintf("%s%d", challenge.Salt, i)
		testHash, err := hashData(challenge.Algorithm, testData)
		if err != nil {
			return "", err
		}

		if testHash == challenge.Challenge {
			// Found solution!
			return CreateSolutionPayload(
				challenge.Algorithm,
				challenge.Challenge,
				challenge.Salt,
				i,
				hmacKey,
			)
		}
	}

	return "", fmt.Errorf("no solution found within %d attempts", maxAttempts)
}

// ValidateChallenge validates a challenge structure
func ValidateChallenge(challenge *Challenge, hmacKey string) bool {
	// Signature is HMAC of the challenge hash only
	expectedSignature, err := createHMAC(hmacKey, challenge.Challenge)
	if err != nil {
		return false
	}

	return challenge.Signature == expectedSignature
}
