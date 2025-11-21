package altcha

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"image"
	"image/color"
	"image/png"
	"strings"
	"time"
	
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// ChallengeOptions contains options for creating a challenge
type ChallengeOptions struct {
	Algorithm  string
	MaxNumber  int
	SaltLength int
	HMACKey    string
	Expires    time.Time
}

// CodeChallenge represents an optional visual code challenge
type CodeChallenge struct {
	Image  string `json:"image"`  // base64-encoded PNG
	Length int    `json:"length"` // code length
}

// Challenge represents an ALTCHA challenge
type Challenge struct {
	Algorithm     string         `json:"algorithm"`
	Challenge     string         `json:"challenge"`
	MaxNumber     int            `json:"maxNumber"`
	Salt          string         `json:"salt"`
	Signature     string         `json:"signature"`
	CodeChallenge *CodeChallenge `json:"codeChallenge,omitempty"`
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

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(solution.Signature), []byte(expectedSignature)) != 1 {
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

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(challenge.Signature), []byte(expectedSignature)) == 1
}

// GenerateCodeChallenge creates a visual code challenge (image with random code)
func GenerateCodeChallenge(length int) (*CodeChallenge, string, error) {
	if length <= 0 {
		length = 6
	}
	
	// Generate random alphanumeric code
	code, err := generateRandomCode(length)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate code: %w", err)
	}
	
	// Create image with code
	imageData, err := createCodeImage(code)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create image: %w", err)
	}
	
	return &CodeChallenge{
		Image:  imageData,
		Length: length,
	}, code, nil
}

// generateRandomCode creates a random alphanumeric code
func generateRandomCode(length int) (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude similar characters
	code := make([]byte, length)
	randomBytes := make([]byte, length)
	
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	
	for i := range code {
		code[i] = charset[int(randomBytes[i])%len(charset)]
	}
	
	return string(code), nil
}

// createCodeImage generates a PNG image with the given code
func createCodeImage(code string) (string, error) {
	// Image dimensions
	width := 200
	height := 60
	
	// Create image
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	
	// Fill background
	bgColor := color.RGBA{240, 240, 240, 255}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, bgColor)
		}
	}
	
	// Add noise lines
	noiseColor := color.RGBA{200, 200, 200, 255}
	for i := 0; i < 5; i++ {
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)
		x1 := int(randomBytes[0]) % width
		y1 := int(randomBytes[1]) % height
		x2 := int(randomBytes[2]) % width
		y2 := int(randomBytes[3]) % height
		drawLine(img, x1, y1, x2, y2, noiseColor)
	}
	
	// Draw text
	textColor := color.RGBA{0, 0, 0, 255}
	point := fixed.Point26_6{X: fixed.Int26_6(20 * 64), Y: fixed.Int26_6(40 * 64)}
	
	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(textColor),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	
	// Draw each character with slight offset
	for i, ch := range code {
		d.Dot.X = fixed.Int26_6((20 + i*25) * 64)
		d.DrawString(string(ch))
	}
	
	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	
	// Return as base64
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// drawLine draws a simple line on the image
func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.Color) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	sx, sy := 1, 1
	if x1 >= x2 {
		sx = -1
	}
	if y1 >= y2 {
		sy = -1
	}
	err := dx - dy
	
	for {
		img.Set(x1, y1, c)
		if x1 == x2 && y1 == y2 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x1 += sx
		}
		if e2 < dx {
			err += dx
			y1 += sy
		}
	}
}

// abs returns absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
