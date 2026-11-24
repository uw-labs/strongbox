package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
)

// The expected hashes come from the standard library of Go 1.26, the last
// release whose compress/flate output matches what is already committed in
// encrypted files. If this fails, compress() has changed and every file
// encrypted afterwards will differ from the one before it.
func TestCompressStable(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	rnd := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}

	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, "30e6fa98fb48c2b132824d1ac5e2243c0be9e9082ff32598d34d7687ca7f6c7f"},
		{"small", []byte("hello strongbox\n"), "9212be32f1dc3da5b8269b986cf8a0be39062c2aa5f386d44d239803fa1b23c9"},
		{"random-300", rnd(300), "1f325689c200366001f2f825cd69497acf6a2efa38a71041bb35d9ee6c12af5e"},
		{"random-70000", rnd(70000), "fb5217cbe8bb063a929b1b49d9275eb6b0a2cf287697f032e6b8c280812a8d5b"},
		{"text", bytes.Repeat([]byte("apiVersion: v1\nkind: Secret\ndata:\n  key: value\n"), 400), "2b417dc8533d9612b308f4cb899a30650e699757ef3d74aedb6061358d693f64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compress(tt.in)
			sum := sha256.Sum256(c)
			if got := hex.EncodeToString(sum[:]); got != tt.want {
				t.Fatalf("compressed output changed: got %s, want %s", got, tt.want)
			}
			if out := decompress(c); !bytes.Equal(out, tt.in) {
				t.Fatal("decompress did not return the input")
			}
		})
	}
}

// The fixture was written by the released v2.1.0 binary (Go 1.21) with the key
// bytes 0..31. Encrypting the same plaintext must give the same file, and the
// file must still decrypt. This also covers the SIV library, the base64
// encoding and the line wrapping, which the compressor test does not.
func TestEncryptMatchesRelease(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plain, err := os.ReadFile("testdata/golden-plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/golden-v2.1.0.enc")
	if err != nil {
		t.Fatal(err)
	}

	got, err := encrypt(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatal("encrypt output differs from the file written by v2.1.0")
	}

	dec, err := decrypt(fixture, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("decrypting the v2.1.0 file did not return the plaintext")
	}
}
