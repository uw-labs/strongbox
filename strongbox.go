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
	keyLoader = key

	kr            keyRing
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
	kr = &fileKeyRing{fileName: filepath.Join(u.HomeDir, ".strongbox_keyring")}
}

func main() {
	app := cli.App("strongbox", "Frictionless encryption workflow for git users")
	app.Command("install", "configure git for strongbox use", func(cmd *cli.Cmd) {
		cmd.Action = func() {
			install()
		}
	})
	app.Command("import", "import a key into your keyring", func(cmd *cli.Cmd) {
		app.Spec = "[-f]"
		filename := cmd.StringOpt("f filename", "", "file to import the strongbox keys")
		cmd.Action = func() {
			if filename != nil {
				f, err := os.Open(*filename)
				if err != nil {
					importKeys(f)
				}
				log.Fatal(err)
			} else {
				importKeys(os.Stdin)
			}
		}
	})
	app.Command("gen-key", "Generate a new key and add it to your strongbox keyring", func(cmd *cli.Cmd) {
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
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(string(out))
		}
	}
	log.Println("git global configuration updated successfully")
}

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

func filter(r io.Reader, w io.Writer, filename string, f func(b []byte, key []byte) ([]byte, error)) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	key, err := keyLoader(filename)
	if err != nil {
		log.Println(err)
		if _, err = io.Copy(w, bytes.NewReader(in)); err != nil {
			log.Println(err)
		}
		return
	}

	out, err := f(in, key)
	if err != nil {
		log.Println(err)
		out = in
	}
	if _, err := io.Copy(w, bytes.NewReader(out)); err != nil {
		log.Println(err)
	}
}

func importKeys(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	var keyEntries []keyEntry
	if err := yaml.Unmarshal(data, &keyEntries); err != nil {
		return err
	}
	if err := kr.Load(); err != nil {
		return err
	}
	for _, keyEntry := range keyEntries {
		if _, err = kr.Key([]byte(keyEntry.KeyID)); err == nil {
			kr.AddKey(keyEntry.Description, []byte(keyEntry.KeyID), []byte(keyEntry.Key))
		}
	}
	return kr.Save()
}

func encrypt(b []byte, key []byte) ([]byte, error) {

	if bytes.HasPrefix(b, prefix) {
		// File is encrypted, copy it as is
		return nil, errors.New("already encrypted")
	}

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

type keyRing interface {
	Load() error
	Save() error
	AddKey(name string, keyID []byte, key []byte)
	Key(keyID []byte) ([]byte, error)
}

type fileKeyRing struct {
	fileName   string
	KeyEntries []keyEntry
}

type keyEntry struct {
	Description string `yaml:"description"`
	KeyID       string `yaml:"key-id"`
	Key         string `yaml:"key"`
}

func (kr *fileKeyRing) AddKey(desc string, keyID []byte, key []byte) {
	kr.KeyEntries = append(kr.KeyEntries, keyEntry{
		Description: desc,
		KeyID:       string(encode(keyID[:])),
		Key:         string(encode(key[:])),
	})

}

func (kr *fileKeyRing) Key(keyID []byte) ([]byte, error) {
	b64 := string(encode(keyID[:]))

	for _, ke := range kr.KeyEntries {
		if ke.KeyID == b64 {
			dec, err := decode([]byte(ke.Key))
			if err != nil {
				return []byte{}, err
			}
			if len(dec) != 32 {
				return []byte{}, fmt.Errorf("unexpected length of key: %d", len(dec))
			}
			return dec, nil
		}
	}

	return []byte{}, fmt.Errorf("key not found for key-id '%s'", b64)
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
