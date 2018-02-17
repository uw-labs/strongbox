package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
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
	"gopkg.in/yaml.v2"
)

var (
	keyLoader = key

	kr            keyRing
	prefix        = []byte("# STRONGBOX ENCRYPTED RESOURCE ;")
	defaultPrefix = "# STRONGBOX ENCRYPTED RESOURCE ; See https://github.com/uw-labs/strongbox ; strongbox-version: %s ; key-id: %s\n"

	keyNotFound = errors.New("key not found")

	// flags
	flagGitConfig = flag.Bool("git-config", false, "Configure git for strongbox use")
	flagGenKey    = flag.String("gen-key", "", "Generate a new key and add it to your strongbox keyring")
	flagClean     = flag.String("clean", "", "intended to be called internally by git")
	flagSmudge    = flag.String("smudge", "", "intended to be called internally by git")
	flagDiff      = flag.String("diff", "", "intended to be called internally by git")
	flagVersion   = flag.Bool("version", false, "Strongbox version")

	version = ""
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -git-config\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -gen-key key-name\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -version\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("strongbox: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Usage = usage
	flag.Parse()

	// Set up keyring file name
	home := ""
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

	if *flagVersion || (flag.NArg() == 1 && flag.Arg(0) == "version") {
		fmt.Println(version)
		return
	}

	// only a single flag has been set
	if flag.NFlag() != 1 {
		usage()
	}

	if *flagGitConfig {
		gitConfig()
		return
	}

	if *flagGenKey != "" {
		genKey(*flagGenKey)
		return
	}

	if *flagClean != "" {
		clean(os.Stdin, os.Stdout, *flagClean)
		return
	}
	if *flagSmudge != "" {
		smudge(os.Stdin, os.Stdout, *flagSmudge)
		return
	}
	if *flagDiff != "" {
		diff(*flagDiff)
		return
	}
}

func gitConfig() {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox.clean", "strongbox -clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.smudge", "strongbox -smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox.textconv", "strongbox -diff"},
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
	// Read the file, fail on error
	in, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	// Check the file is plaintext, if its an encrypted strongbox file, copy as is, and exit 0
	if bytes.HasPrefix(in, prefix) {
		_, err := io.Copy(w, bytes.NewReader(in))
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	// File is plaintext and needs to be encrypted, get the key, fail on error
	key, keyID, err := keyLoader(filename)
	if err != nil {
		log.Fatal(err)
	}
	// encrypt the file, fail on error
	out, err := encrypt(in, key, keyID)
	if err != nil {
		log.Fatal(err)
	}
	// write out encrypted file, fail on error
	_, err = io.Copy(w, bytes.NewReader(out))
	if err != nil {
		log.Fatal(err)
	}
}

// Called by git on `git checkout`
func smudge(r io.Reader, w io.Writer, filename string) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	// file is a non-strongbox file, copy as is and exit
	if !bytes.HasPrefix(in, prefix) {
		_, err := io.Copy(w, bytes.NewReader(in))
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	key, _, err := keyLoader(filename)
	if err != nil {
		// don't log error if its keyNotFound
		switch err {
		case keyNotFound:
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
	if _, err := io.Copy(w, bytes.NewReader(out)); err != nil {
		log.Println(err)
	}
}

func encrypt(b, key, keyID []byte) ([]byte, error) {
	b = compress(b)
	out, err := siv.Encrypt(nil, key, b, nil)
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, []byte(fmt.Sprintf(defaultPrefix, version, string(encode(keyID[:]))))...)
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

func key(filename string) ([]byte, []byte, error) {
	keyID, err := findKey(filename)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	err = kr.Load()
	if err != nil {
		return []byte{}, []byte{}, err
	}

	key, err := kr.Key(keyID)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return key, keyID, nil
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

	return []byte{}, keyNotFound
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
