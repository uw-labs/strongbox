package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
)

const version = "0.1.0-dev"

var (
	keyLoader = key

	kr            keyRing
	prefix        = []byte("# STRONGBOX ENCRYPTED RESOURCE ;")
	defaultPrefix = []byte("# STRONGBOX ENCRYPTED RESOURCE ; See https://github.com/uw-labs/strongbox\n")

	errKeyNotFound = errors.New("key not found")
)

func main() {
	log.SetPrefix("strongbox: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app := cli.NewApp()

	app.Name = "strongbox"
	app.Version = version
	app.Usage = ""
	app.Description = "Encryption for git users."

	// Set up keyring file name
	var home string
	u, err := user.Current()
	if err != nil {
		// Possibly compiled without CGO and syscall isn't implemented,
		// try to grab the environment variable
		home = os.Getenv("HOME")
		if home == "" {
			log.Fatal("Could not call os/user.Current() or find $HOME. Please recompile with CGO enabled or set $HOME")
		}
	} else {
		home = u.HomeDir
	}

	kr = &fileKeyRing{fileName: filepath.Join(home, ".strongbox_keyring")}

	app.Commands = []cli.Command{
		{
			Name:        "git-config",
			Description: "Configure git for strongbox use",
			Action:      commandGitConfig,
		},
		{
			Name:        "gen-key",
			Description: "Generate a new key and add it to your strongbox keyring",
			Action:      commandGenKey,
		},
		{
			Name:        "decrypt",
			Description: "Decrypt single resource",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key",
					Usage: "Private key",
				},
			},
			Action: commandDecrypt,
		},

		{
			Name:        "clean",
			Description: "intended to be called internally by git",
			Action:      commandClean,
		},
		{
			Name:        "smudge",
			Description: "intended to be called internally by git",
			Action:      commandSmudge,
		},
		{
			Name:        "diff",
			Description: "intended to be called internally by git",
			Action:      commandDiff,
		},

		{
			Name:        "version",
			Description: "Print the application version and exit",
			Action: func(c *cli.Context) (err error) {
				fmt.Println(version)
				return
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func commandGitConfig(c *cli.Context) (err error) {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox.clean", "strongbox clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.smudge", "strongbox smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox.textconv", "strongbox diff"},
	}
	for _, command := range args {
		cmd := exec.Command("git", command...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out))
		}
	}
	log.Println("git global configuration updated successfully")

	return
}

func commandDecrypt(c *cli.Context) (err error) {
	if !c.IsSet("key") {
		return errors.New("decrypt requires --key to be set")
	}
	key := c.String("key")

	var input io.Reader
	if c.Args().First() == "" {
		// no file passed, try to read stdin
		input = os.Stdin
	} else {
		input, err = os.Open(c.Args().First())
		if err != nil {
			return errors.Wrap(err, "failed to open input file")
		}
	}

	contents, err := ioutil.ReadAll(input)
	if err != nil {
		return errors.Wrap(err, "failed to read input stream")
	}

	dk, err := decode([]byte(key))
	if err != nil {
		return errors.Wrap(err, "failed to decode private key")
	}

	out, err := decrypt(contents, dk)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}

	fmt.Printf("%s", out)
	return
}

func commandGenKey(c *cli.Context) (err error) {
	err = kr.Load()
	if err != nil && !os.IsNotExist(err) {
		return
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	keyID := sha256.Sum256(key)

	kr.AddKey(c.Args().First(), keyID[:], key)

	err = kr.Save()
	if err != nil {
		return
	}

	return
}

func commandClean(c *cli.Context) (err error) {
	return clean(os.Stdin, os.Stdout, c.Args().First())
}

func commandSmudge(c *cli.Context) (err error) {
	return smudge(os.Stdin, os.Stdout, c.Args().First())
}

func commandDiff(c *cli.Context) (err error) {
	return diff(c.Args().First())
}

func clean(r io.Reader, w io.Writer, filename string) (err error) {
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
	key, err := keyLoader(filename)
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

func smudge(r io.Reader, w io.Writer, filename string) (err error) {
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

	key, err := keyLoader(filename)
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

	return []byte{}, errKeyNotFound
}

func (kr *fileKeyRing) Load() error {

	bytes, err := ioutil.ReadFile(kr.fileName)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bytes, kr)
	return err
}

func (kr *fileKeyRing) Save() error {
	ser, err := yaml.Marshal(kr)
	if err != nil {
		log.Fatal(err)
	}

	return ioutil.WriteFile(kr.fileName, ser, 0600)
}
