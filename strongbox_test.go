package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	priv  []byte
	plain = []byte("hello world. this is some plain text for testing")
)

func TestMain(m *testing.M) {
	var err error
	priv = make([]byte, 32)
	_, err = rand.Read(priv)
	if err != nil {
		panic(err)
	}

	keyLoader = testKeyLoader

	os.Exit(m.Run())
}

func testKeyLoader(string) ([]byte, error) {
	return priv, nil
}

func TestMultipleClean(t *testing.T) {
	assert := assert.New(t)

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	var doubleCleaned bytes.Buffer
	clean(bytes.NewReader(cleaned.Bytes()), &doubleCleaned, "")

	assert.Equal(cleaned.String(), doubleCleaned.String())
}

func TestSmudgeAlreadyPlaintext(t *testing.T) {
	assert := assert.New(t)

	var smudged bytes.Buffer
	smudge(bytes.NewReader(plain), &smudged, "")

	assert.Equal(string(plain), smudged.String())
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	assert.NotEqual(plain, cleaned.Bytes())

	var smudged bytes.Buffer
	smudge(bytes.NewReader(cleaned.Bytes()), &smudged, "")

	assert.Equal(string(plain), smudged.String())
}

func TestDeterministic(t *testing.T) {
	assert := assert.New(t)

	var cleaned1 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned1, "")

	var cleaned2 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned2, "")

	assert.Equal(cleaned1.String(), cleaned2.String())
}

func BenchmarkRoundTripPlain(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var cleaned bytes.Buffer
		clean(bytes.NewReader(plain), &cleaned, "")

		var smudged bytes.Buffer
		smudge(bytes.NewReader(cleaned.Bytes()), &smudged, "")
	}
}
