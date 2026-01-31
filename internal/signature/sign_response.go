package signature

import (
	"crypto/ed25519"
	"encoding/base64"
	"sync"

	"github.com/gofiber/fiber/v2"
)

// --- Private Constants & Globals ---

var (
	// Pre-allocated header key to avoid string-to-byte conversion on every request.
	headerKey = []byte("X-Signature-Ed25519")

	// Calculate buffer sizes once at startup.
	// Ed25519 signatures are always 64 bytes.
	sigSize = ed25519.SignatureSize
	// Base64 encoding requires ~88 bytes for 64 bytes of input.
	b64Size = base64.StdEncoding.EncodedLen(sigSize)

	// Memory pool to reuse the destination buffer for Base64 encoding.
	// This saves us from allocating a new string/byte slice for the header value every time.
	bufferPool = sync.Pool{
		New: func() interface{} {
			// Allocate a slice with exact capacity needed
			b := make([]byte, b64Size)
			return &b
		},
	}
)

// --- Core Logic ---

// signResponseCore is the internal function that performs the signing logic.
// It is separated to keep the public API file clean.
func SignResponse(c *fiber.Ctx, privateKey ed25519.PrivateKey) {
	bodyBytes := c.Response().Body()

	// Note: ed25519.Sign internally allocates 64 bytes. This is unavoidable
	// without rewriting the crypto library, but it's small and short-lived.
	signature := ed25519.Sign(privateKey, bodyBytes)

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr // Dereference to get the actual slice

	// Defer is slightly slower (~5ns), but safer. For extreme optimization,
	defer bufferPool.Put(bufPtr)

	base64.StdEncoding.Encode(buf, signature)

	// SetCanonical copies the bytes into the response immediately,
	c.Response().Header.SetCanonical(headerKey, buf)
}
