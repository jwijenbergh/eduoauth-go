
package eduoauth

import (
	"bytes"
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
