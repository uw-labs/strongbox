package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func loadKey(filename string, kr keyRing) ([]byte, error) {
	keyID, err := findKey(filename)
	if err != nil {
		return []byte{}, err
	}

	err = kr.Load()
	if err != nil {
		return []byte{}, err
	}

	key, err := kr.Key(keyID)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

func findKey(filename string) ([]byte, error) {
	path := filepath.Dir(filename)
	for {
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			keyFilename := filepath.Join(path, ".strongbox-keyid")
			if keyFile, err := os.Stat(keyFilename); err == nil && !keyFile.IsDir() {
				return readKey(keyFilename)
			}
		}
		if path == "." {
			break
		}
		path = filepath.Dir(path)
	}
	return []byte{}, fmt.Errorf("failed to find key id for file %s", filename)
}

func readKey(filename string) ([]byte, error) {
	fp, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}

	b64 := strings.TrimSpace(string(fp))
	b, err := decode([]byte(b64))
	if err != nil {
		return []byte{}, err
	}
	if len(b) != 32 {
		return []byte{}, fmt.Errorf("unexpected key length %d", len(b))
	}
	return b, nil
}
