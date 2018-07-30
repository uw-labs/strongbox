package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/jacobsa/crypto/siv"
	"github.com/pkg/errors"
)

func clean(r io.Reader, w io.Writer, filename string, kr keyRing) (err error) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}

	// Check the file is plaintext, if its an encrypted strongbox file, copy as is, and exit 0
	if bytes.HasPrefix(in, prefix) {
		_, err = io.Copy(w, bytes.NewReader(in))
		if err != nil {
			return
		}
		return
	}

	// File is plaintext and needs to be encrypted, get the key, fail on error
	key, err := loadKey(filename, kr)
	if err != nil {
		return
	}

	out, err := encrypt(in, key)
	if err != nil {
		return
	}

	_, err = io.Copy(w, bytes.NewReader(out))
	if err != nil {
		return
	}

	return
}

func smudge(r io.Reader, w io.Writer, filename string, kr keyRing) (err error) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		return errors.Wrap(err, "failed to read input stream")
	}

	// file is a non-strongbox file, copy as is and exit
	if !bytes.HasPrefix(in, prefix) {
		_, err = io.Copy(w, bytes.NewReader(in))
		if err != nil {
			return errors.Wrap(err, "failed to copy to output stream")
		}
		return
	}

	key, err := loadKey(filename, kr)
	if err != nil {
		// don't log error if its keyNotFound
		switch err {
		case errKeyNotFound:
		default:
			log.Println(err)
		}
		// Couldn't load the key, just copy as is and return
		if _, err = io.Copy(w, bytes.NewReader(in)); err != nil {
			log.Println(err)
		}
		return
	}

	out, err := decrypt(in, key)
	if err != nil {
		log.Println(err)
		out = in
	}
	if _, err = io.Copy(w, bytes.NewReader(out)); err != nil {
		return
	}

	return
}

func diff(filename string) (err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer func() {
		if err = f.Close(); err != nil {
			return
		}
	}()

	_, err = io.Copy(os.Stdout, f)
	if err != nil {
		return
	}

	return
}

func encrypt(b []byte, key []byte) ([]byte, error) {
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
	b, err = ioutil.ReadAll(zr)
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

func decrypt(enc []byte, priv []byte) ([]byte, error) {
	// strip prefix and any comment up to end of line
	spl := bytes.SplitN(enc, []byte("\n"), 2)
	if len(spl) != 2 {
		return nil, errors.New("Couldn't split on end of line")
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
