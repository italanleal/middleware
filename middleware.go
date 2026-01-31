package middleware

import (
	"crypto/ed25519"

	"github.com/gofiber/fiber/v2"
	"github.com/italanleal/middleware/internal/signature"
)

/*
NewSignResponseMiddleware returns a Fiber middleware that ensures non-repudiation by signing
the response body with an Ed25519 private key.

It executes the request handler first, captures the final response body, generates a digital signature,
and attaches it to the "X-Signature-Ed25519" header.
*/
func NewSignResponseMiddleware(privateKey ed25519.PrivateKey) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			return err
		}

		signature.SignResponse(c, privateKey)

		return nil
	}
}
