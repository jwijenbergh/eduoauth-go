
package eduoauth

import (
	"bytes"
	"net/url"
	"testing"
)

func TestMakeRandomByteSlice(t *testing.T) {
	random, randomErr := makeRandomByteSlice(32)
	if randomErr != nil {
		t.Fatalf("Got: %v, want: nil", randomErr)
	}
	if len(random) != 32 {
		t.Fatalf("Got length: %d, want length: 32", len(random))
	}

	random2, randomErr2 := makeRandomByteSlice(32)
	if randomErr2 != nil {
		t.Fatalf("2, Got: %v, want: nil", randomErr)
	}

	if bytes.Equal(random2, random) {
		t.Fatalf("Two random byteslices are the same: %v, %v", random2, random)
	}
}

func Test_verifiergen(t *testing.T) {
	v, err := genVerifier()
	if err != nil {
		t.Fatalf("Gen verifier error: %v", err)
	}

	// Verifier must be at minimum 43 and at max 128 characters...
	// However... Our verifier is exactly 43!
	if len(v) != 43 {
		t.Fatalf(
			"Got verifier length: %d, want a verifier with at least 43 characters",
			len(v),
		)
	}

	_, err = url.QueryUnescape(v)
	if err != nil {
		t.Fatalf("Verifier: %s can not be unescaped", v)
	}
}

func Test_stategen(t *testing.T) {
	s1, err := genState()
	if err != nil {
		t.Fatalf("Error when generating state 1: %v", err)
	}

	s2, err := genState()
	if err != nil {
		t.Fatalf("Error when generating state 2: %v", err)
	}

	if s1 == s2 {
		t.Fatalf("State: %v, equal to: %v", s1, s2)
	}
}

func Test_challengergen(t *testing.T) {
	verifier := "test"
	// Calculated using: base64.urlsafe_b64encode(hashlib.sha256("test".encode("utf-8")).digest()).decode("utf-8").replace("=", "") in Python
	// This test might not be the best because we're now comparing two different implementations, but at least it gives us a way to see if we messed something up in a commit
	want := "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
	got := genChallengeS256(verifier)

	if got != want {
		t.Fatalf("Challenger not equal, got: %v, want: %v", got, want)
	}
}
