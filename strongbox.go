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
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/jacobsa/crypto/siv"
	"github.com/jawher/mow.cli"
	"gopkg.in/yaml.v2"
)

var (
	keyLoader func(filename string) (privateKey []byte, err error) = keyPair

	keyRing       KeyRing
	prefix        = []byte("# STRONGBOX ENCRYPTED RESOURCE ;")
	defaultPrefix = []byte("# STRONGBOX ENCRYPTED RESOURCE ; See https://github.com/uw-labs/strongbox\n")
)

func init() {
	log.SetPrefix("strongbox : ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Set up keyring file name
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	keyRing = &fileKeyRing{fileName: filepath.Join(u.HomeDir, ".strongbox_keyring")}
}

func main() {
	app := cli.App("strongbox", "Frictionless encryption workflow for git users")
	app.Command("install", "configure git for strongbox use", func(cmd *cli.Cmd) {
		cmd.Action = func() {
			install()
		}
	})
	app.Command("gen-key", "Generate a new public/private key pair and add it to your strongbox keyring", func(cmd *cli.Cmd) {
		desc := cmd.StringArg("DESCRIPTION", "new key", "a description for the generated key")
		cmd.Action = func() {
			genKey(*desc)
		}
	})
	app.Command("clean", "intended to be called internally by git", func(cmd *cli.Cmd) {
		filename := cmd.String(cli.StringArg{
			Name: "FILENAME",
			Desc: "Full relative path name of file. Invoked by git",
		})
		cmd.Action = func() {
			clean(os.Stdin, os.Stdout, *filename)
		}
	})
	app.Command("smudge", "intended to be called internally by git", func(cmd *cli.Cmd) {
		filename := cmd.String(cli.StringArg{
			Name: "FILENAME",
			Desc: "Full relative path name of file. Invoked by git",
		})
		cmd.Action = func() {
			smudge(os.Stdin, os.Stdout, *filename)
		}
	})
	app.Command("diff", "intended to be called internally by git", func(cmd *cli.Cmd) {
		filename := cmd.String(cli.StringArg{
			Name: "FILENAME",
			Desc: "Full relative path name of file. Invoked by git",
		})
		cmd.Action = func() {
			diff(*filename)
		}
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func install() {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox.clean", "strongbox clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.smudge", "strongbox smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox.textconv", "strongbox diff"},
	}
	for _, command := range args {
		cmd := exec.Command("git", command...)
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	}
	log.Println("git global configuration updated successfully")
}

func genKey(desc string) {
	err := keyRing.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	priv := make([]byte, 32)
	_, err = rand.Read(priv)
	if err != nil {
		log.Fatal(err)
	}

	pub := sha256.Sum256(priv)

	keyRing.AddKey(desc, pub[:], priv)

	err = keyRing.Save()
	if err != nil {
		log.Fatal(err)
	}
}

func diff(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	_, err = io.Copy(os.Stdout, f)
	if err != nil {
		log.Fatal(err)
	}
}

func clean(r io.Reader, w io.Writer, filename string) {
	filter(r, w, filename, encrypt)
}

func smudge(r io.Reader, w io.Writer, filename string) {
	filter(r, w, filename, decrypt)
}

func filter(r io.Reader, w io.Writer, filename string, f func(b []byte, priv []byte) ([]byte, error)) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := keyLoader(filename)
	if err != nil {
		log.Println(err)
		if _, err = io.Copy(w, bytes.NewReader(in)); err != nil {
			log.Println(err)
		}
		return
	}

	out, err := f(in, priv)
	if err != nil {
		log.Println(err)
		out = in
	}
	if _, err := io.Copy(w, bytes.NewReader(out)); err != nil {
		log.Println(err)
	}
}

func encrypt(b []byte, priv []byte) ([]byte, error) {

	if bytes.HasPrefix(b, prefix) {
		// File is encrypted, copy it as is
		return nil, errors.New("already encrypted")
	}

	b = compress(b)

	out, err := siv.Encrypt(nil, priv, b, nil)
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

	if !bytes.Equal(prefix, enc[0:len(prefix)]) {
		return nil, errors.New("unexpected prefix")
	}

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

func keyPair(filename string) ([]byte, error) {
	pub, err := findKey(filename)
	if err != nil {
		return []byte{}, err
	}

	err = keyRing.Load()
	if err != nil {
		return []byte{}, err
	}

	priv, err := keyRing.Private(pub)
	if err != nil {
		return []byte{}, err
	}

	return priv, nil
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
		path = filepath.Dir(path)
		if path == "." {
			break
		}
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

type KeyRing interface {
	Load() error
	Save() error
	AddKey(name string, public []byte, private []byte)
	Private(public []byte) ([]byte, error)
}

type fileKeyRing struct {
	fileName string
	Keys     []key
}

type key struct {
	Description string
	Public      string
	Private     string
}

func (kr *fileKeyRing) AddKey(desc string, public []byte, private []byte) {
	kr.Keys = append(kr.Keys, key{
		Description: desc,
		Public:      string(encode(public[:])),
		Private:     string(encode(private[:])),
	})

}

func (kr *fileKeyRing) Private(pub []byte) ([]byte, error) {
	b64 := string(encode(pub[:]))

	for _, k := range kr.Keys {
		if k.Public == b64 {
			dec, err := decode([]byte(k.Private))
			if err != nil {
				return []byte{}, err
			}
			if len(dec) != 32 {
				return []byte{}, fmt.Errorf("unexpected length of private key: %d", len(dec))
			}
			return dec, nil
		}
	}

	return []byte{}, fmt.Errorf("private key not found for public key '%s'", b64)
}

func (kr *fileKeyRing) Load() error {

	bytes, err := ioutil.ReadFile(kr.fileName)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bytes, kr)
	if err != nil {
		return err
	}
	return nil
}

func (kr *fileKeyRing) Save() error {
	ser, err := yaml.Marshal(kr)
	if err != nil {
		log.Fatal(err)
	}

	return ioutil.WriteFile(kr.fileName, ser, 0600)
}
