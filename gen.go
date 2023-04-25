package eduoauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// makeRandomByteSlice creates a cryptographically random bytes slice of `size`
// It returns the byte slice (or nil if error) and an error if it could not be generated.
func makeRandomByteSlice(n int) ([]byte, error) {
	bs := make([]byte, n)
	if _, err := rand.Read(bs); err != nil {
		return nil, err
	}
	return bs, nil
}

// genState generates a random base64 string to be used for state
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-4.1.1
// "state":  OPTIONAL.  An opaque value used by the client to maintain
// state between the request and callback.  The authorization server
// includes this value when redirecting the user agent back to the
// client.
// We implement it similarly to the verifier.
func genState() (string, error) {
	bs, err := makeRandomByteSlice(32)
	if err != nil {
		return "", err
	}

	// For consistency, we also use raw url encoding here
	return base64.RawURLEncoding.EncodeToString(bs), nil
}

// genChallengeS256 generates a sha256 base64 challenge from a verifier
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-7.8
func genChallengeS256(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))

	// We use raw url encoding as the challenge does not accept padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// genVerifier generates a verifier
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-4.1.1
// The code_verifier is a unique high-entropy cryptographically random
// string generated for each authorization request, using the unreserved
// characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a
// minimum length of 43 characters and a maximum length of 128
// characters.
// We implement it according to the note:
//
//	NOTE: The code verifier SHOULD have enough entropy to make it
//	impractical to guess the value.  It is RECOMMENDED that the output of
//	a suitable random number generator be used to create a 32-octet
//	sequence.  The octet sequence is then base64url-encoded to produce a
//	43-octet URL safe string to use as the code verifier.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func genVerifier() (string, error) {
	random, err := makeRandomByteSlice(32)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(random), nil
}
