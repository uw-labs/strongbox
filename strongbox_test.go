package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	priv []byte
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

	plain := []byte("hello world. this is some plain text for testing")

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	var doubleCleaned bytes.Buffer
	clean(bytes.NewReader(cleaned.Bytes()), &doubleCleaned, "")

	assert.Equal(cleaned.Bytes(), doubleCleaned.Bytes())
}

func TestSmudgeAlreadyPlaintext(t *testing.T) {
	assert := assert.New(t)

	plain := []byte("hello world. this is some plain text for testing")

	var smudged bytes.Buffer
	smudge(bytes.NewReader(plain), &smudged, "")

	assert.Equal(plain, smudged.Bytes())
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)

	plain := []byte("hello world. this is some plain text for testing")

	var cleaned bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned, "")

	assert.NotEqual(plain, cleaned.Bytes())

	var smudged bytes.Buffer
	smudge(bytes.NewReader(cleaned.Bytes()), &smudged, "")

	assert.Equal(plain, smudged.Bytes())
}

func TestDeterministic(t *testing.T) {
	assert := assert.New(t)

	plain := []byte("hello world. this is some plain text for testing")

	var cleaned1 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned1, "")

	var cleaned2 bytes.Buffer
	clean(bytes.NewReader(plain), &cleaned2, "")

	assert.Equal(cleaned1, cleaned2)
}
