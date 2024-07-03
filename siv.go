package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jacobsa/crypto/siv"
)

var (
	keyLoader     = key
	kr            keyRing
	prefix        = []byte("# STRONGBOX ENCRYPTED RESOURCE ;")
	defaultPrefix = []byte("# STRONGBOX ENCRYPTED RESOURCE ; See https://github.com/uw-labs/strongbox\n")

	errKeyNotFound = errors.New("key not found")
)

func genKey(desc string) {
	err := kr.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}

	keyID := sha256.Sum256(key)

	kr.AddKey(desc, keyID[:], key)

	err = kr.Save()
	if err != nil {
		log.Fatal(err)
	}
}

// recursiveDecrypt will try and recursively decrypt files
// if 'key' is provided then it will decrypt all encrypted files with given key
// otherwise it will find key based on file location
// if error is generated in finding key or in decryption then it will continue with next file
// function will only return early if it failed to read/write files
func recursiveDecrypt(target string, givenKey []byte) error {
	var decErrors []string
	err := filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
		// always return on error
		if err != nil {
			return err
		}

		// only process files
		if entry.IsDir() {
			// skip .git directory
			if entry.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer file.Close()

		// for optimisation only read required chunk of the file and verify if encrypted
		chunk := make([]byte, len(defaultPrefix))
		_, err = file.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}

		if !bytes.HasPrefix(chunk, prefix) {
			return nil
		}

		key := givenKey
		if len(key) == 0 {
			key, err = keyLoader(path)
			if err != nil {
				// continue with next file
				decErrors = append(decErrors, fmt.Sprintf("unable to find key file:%s err:%s", path, err))
				return nil
			}
		}

		// read entire file from the beginning
		file.Seek(0, io.SeekStart)
		in, err := io.ReadAll(file)
		if err != nil {
			return err
		}

		out, err := decrypt(in, key)
		if err != nil {
			// continue with next file
			decErrors = append(decErrors, fmt.Sprintf("unable to decrypt file:%s err:%s", path, err))
			return nil
		}

		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := file.Write(out); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(decErrors) > 0 {
		for _, e := range decErrors {
			log.Println(e)
		}
		return fmt.Errorf("unable to decrypt some files")
	}

	return nil
}

func encrypt(b, key []byte) ([]byte, error) {
	b = compress(b)
	out, err := siv.Encrypt(nil, key, b, nil)
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, defaultPrefix...)
	b64 := encode(out)
	for len(b64) > 0 {
		l := 76
		if len(b64) < 76 {
			l = len(b64)
		}
		buf = append(buf, b64[0:l]...)
		buf = append(buf, '\n')
		b64 = b64[l:]
	}
	return buf, nil
}

func decrypt(enc []byte, priv []byte) ([]byte, error) {
	// strip prefix and any comment up to end of line
	spl := bytes.SplitN(enc, []byte("\n"), 2)
	if len(spl) != 2 {
		return nil, errors.New("couldn't split on end of line")
	}
	b64encoded := spl[1]
	b64decoded, err := decode(b64encoded)
	if err != nil {
		return nil, err
	}
	decrypted, err := siv.Decrypt(priv, b64decoded, nil)
	if err != nil {
		return nil, err
	}
	decrypted = decompress(decrypted)
	return decrypted, nil
}

func compress(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	if err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func decompress(b []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}
	b, err = io.ReadAll(zr)
	if err != nil {
		log.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		log.Fatal(err)
	}
	return b
}

func encode(decoded []byte) []byte {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(decoded)))
	base64.StdEncoding.Encode(b64, decoded)
	return b64
}

func decode(encoded []byte) ([]byte, error) {
	decoded := make([]byte, len(encoded))
	i, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded[0:i], nil
}

// key returns private key and error
func key(filename string) ([]byte, error) {
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
				return readKeyID(keyFilename)
			}
		}
		if path == "." {
			break
		}
		path = filepath.Dir(path)
	}
	return []byte{}, fmt.Errorf("failed to find key id for file %s", filename)
}

func readKeyID(filename string) ([]byte, error) {
	fp, err := os.ReadFile(filename)
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

func sivFileToKey(filename string) ([]byte, error) {
	keyID, err := readKeyID(filename)
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
