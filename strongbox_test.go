package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	priv, pub []byte
	plain     = []byte("hello world. this is some plain text for testing")
)

func TestMain(m *testing.M) {
	var err error
	priv = make([]byte, 32)
	_, err = rand.Read(priv)
	if err != nil {
		panic(err)
	}

	keyID := sha256.Sum256(priv)
	pub = keyID[:]

	keyLoader = testKeyLoader

	os.Exit(m.Run())
}

func testKeyLoader(string) ([]byte, []byte, error) {
	return priv, pub, nil
}

func TestMultipleClean(t *testing.T) {
	assert := assert.New(t)

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	var doubleCleaned bytes.Buffer
	clean(bytes.NewReader(cleaned.Bytes()), &doubleCleaned, "")

	if testing.Verbose() {
		fmt.Printf("%s", string(cleaned.Bytes()))
	}

	assert.Equal(string(cleaned.Bytes()), string(doubleCleaned.Bytes()))
}

func TestSmudgeAlreadyPlaintext(t *testing.T) {
	assert := assert.New(t)

	var smudged bytes.Buffer
	smudge(bytes.NewReader(plain), &smudged, "")

	assert.Equal(string(plain), string(smudged.Bytes()))
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	assert.NotEqual(plain, cleaned.Bytes())

	var smudged bytes.Buffer
	smudge(bytes.NewReader(cleaned.Bytes()), &smudged, "")

	assert.Equal(string(plain), string(smudged.Bytes()))
}

func TestDeterministic(t *testing.T) {
	assert := assert.New(t)

	var cleaned1 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned1, "")

	var cleaned2 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned2, "")

	assert.Equal(string(cleaned1.Bytes()), string(cleaned2.Bytes()))
}

func BenchmarkRoundTripPlain(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var cleaned bytes.Buffer
		clean(bytes.NewReader(plain), &cleaned, "")

		var smudged bytes.Buffer
		smudge(bytes.NewReader(cleaned.Bytes()), &smudged, "")
	}
}
