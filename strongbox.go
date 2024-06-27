package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

var (
	flagGitConfig    = flag.Bool("git-config", false, "Configure git for strongbox use")
	flagGenIdentity  = flag.String("gen-identity", "", "Generate a new identity and add it to your strongbox identity file")
	flagIdentityFile = flag.String("identity-file", "", "strongbox identity file, if not set default '$HOME/.strongbox_identity' will be used")

	flagClean  = flag.String("clean", "", "intended to be called internally by git")
	flagSmudge = flag.String("smudge", "", "intended to be called internally by git")
	flagDiff   = flag.String("diff", "", "intended to be called internally by git")

	identityFile string
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -git-config\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox [-identity-file <identity_file_path>] -gen-identity <description>\n")
	fmt.Fprintf(os.Stderr, "\nif -identity-file flag is not set default file '$HOME/.strongbox_identity' or '$STRONGBOX_IDENTITY' will be used\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("strongbox: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Usage = usage
	flag.Parse()

	if *flagGitConfig {
		gitConfig()
		return
	}

	if *flagDiff != "" {
		diff(*flagDiff)
		return
	}

	identityFile = deriveIdentityFile()

	// if identity flag is set replace default
	if *flagIdentityFile != "" {
		identityFile = *flagIdentityFile
	}

	if *flagGenIdentity != "" {
		genIdentity(*flagGenIdentity)
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
}

func deriveIdentityFile() string {
	// try explicitly set STRONGBOX_IDENTITY
	if identity := os.Getenv("STRONGBOX_IDENTITY"); identity != "" {
		return identity
	}
	// Try user.Current which works in most cases, but may not work with CGO disabled.
	u, err := user.Current()
	if err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".strongbox_identity")
	}
	// try HOME env var
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".strongbox_identity")
	}

	log.Fatal("Could not call os/user.Current() or find $STRONGBOX_IDENTITY or $HOME. Please recompile with CGO enabled or set $STRONGBOX_IDENTITY or $HOME")
	// not reached
	return ""
}

func gitConfig() {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox_age.clean", "strongbox -clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox_age.smudge", "strongbox -smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox_age.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox_age.textconv", "strongbox -diff"},
	}
	for _, command := range args {
		cmd := exec.Command("git", command...)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(string(out))
		}
	}
	log.Println("git global configuration updated successfully")
}

func genIdentity(desc string) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	fmt.Printf("public key: %s\n", identity.Recipient().String())

	f, err := os.OpenFile(identityFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	// we assume that file has a trailing newline
	if _, err := f.Write([]byte(fmt.Sprintf("# description: %s\n# public key: %s\n%s\n", desc, identity.Recipient().String(), identity.String()))); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
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
	in, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	// Check the file is plaintext, if its an encrypted age file, copy as is, and exit 0
	if strings.HasPrefix(string(in), armor.Header) {
		_, err := io.Copy(w, bytes.NewReader(in))
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	// File is plaintext and needs to be encrypted, find the recipient, fail on error
	recipient, err := findRecipient(filename)
	if err != nil {
		log.Fatal(err)
	}
	// encrypt the file, fail on error
	armorWriter := armor.NewWriter(w)
	wc, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.Copy(wc, bytes.NewReader(in)); err != nil {
		log.Fatal(err)
	}
	if err := wc.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}
	if err := armorWriter.Close(); err != nil {
		log.Fatalf("Failed to close armor: %v", err)
	}
}

// Called by git on `git checkout`
func smudge(r io.Reader, w io.Writer, filename string) {
	in, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	// file is a non-strongbox file, copy as is and exit
	if !strings.HasPrefix(string(in), armor.Header) {
		_, err := io.Copy(w, bytes.NewReader(in))
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	keyFile, err := os.Open(identityFile)
	if err != nil {
		log.Fatalf("Failed to open private keys file: %v", err)
	}
	identities, err := age.ParseIdentities(keyFile)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	armorReader := armor.NewReader(bytes.NewReader(in))
	ar, err := age.Decrypt(armorReader, identities...)
	if err != nil {
		// Couldn't find the key, just copy as is and return
		if _, err = io.Copy(w, bytes.NewReader(in)); err != nil {
			log.Println(err)
		}
		return
	}
	if _, err := io.Copy(w, ar); err != nil {
		log.Fatal(err)
	}
}

func findRecipient(filename string) (age.Recipient, error) {
	path := filepath.Dir(filename)
	for {
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			keyFilename := filepath.Join(path, ".strongbox_recipient")
			if keyFile, err := os.Stat(keyFilename); err == nil && !keyFile.IsDir() {
				publicKey, err := os.ReadFile(keyFilename)
				if err != nil {
					return nil, err
				}
				return age.ParseX25519Recipient(strings.TrimSuffix(string(publicKey), "\n"))
			}
		}
		if path == "." {
			break
		}
		path = filepath.Dir(path)
	}
	return nil, fmt.Errorf("failed to find recipient for file %s", filename)
}
