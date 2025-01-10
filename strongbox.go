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
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"

	// flags
	flagDecrypt      = flag.Bool("decrypt", false, "Decrypt single resource")
	flagGenIdentity  = flag.String("gen-identity", "", "Generate a new identity and add it to your strongbox identity file")
	flagGenKey       = flag.String("gen-key", "", "Generate a new key and add it to your strongbox keyring")
	flagGitConfig    = flag.Bool("git-config", false, "Configure git for strongbox use")
	flagIdentityFile = flag.String("identity-file", "", "strongbox identity file, if not set default '$HOME/.strongbox_identity' will be used")
	flagKey          = flag.String("key", "", "Private key to use to decrypt")
	flagKeyRing      = flag.String("keyring", "", "strongbox keyring file path, if not set default '$HOME/.strongbox_keyring' will be used")
	flagRecursive    = flag.Bool("recursive", false, "Recursively decrypt all files under given folder, must be used with -decrypt flag")

	flagClean  = flag.String("clean", "", "intended to be called internally by git")
	flagSmudge = flag.String("smudge", "", "intended to be called internally by git")
	flagDiff   = flag.String("diff", "", "intended to be called internally by git")

	flagVersion = flag.Bool("version", false, "Strongbox version")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -git-config\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox [-identity-file PATH] -gen-identity IDENTITY_NAME\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox [-keyring KEYRING_FILEPATH] -gen-key KEY_NAME\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox [-keyring KEYRING_FILEPATH] -decrypt -recursive [-key KEY] [PATH]\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox [-keyring KEYRING_FILEPATH] -decrypt -key KEY [PATH]\n")
	fmt.Fprintf(os.Stderr, "\tstrongbox -version\n")
	fmt.Fprintf(os.Stderr, "\n(age) if -identity-file flag is not set, default '$HOME/.strongbox_identity' will be used\n")
	fmt.Fprintf(os.Stderr, "(siv) if -keyring flag is not set default file '$HOME/.strongbox_keyring' or '$STRONGBOX_HOME/.strongbox_keyring' will be used as keyring\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("strongbox: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Usage = usage
	flag.Parse()

	if *flagVersion || (flag.NArg() == 1 && flag.Arg(0) == "version") {
		fmt.Printf("version=%s commit=%s date=%s builtBy=%s\n", version, commit, date, builtBy)
		return
	}

	if *flagGitConfig {
		gitConfig()
		return
	}

	if *flagDiff != "" {
		diff(*flagDiff)
		return
	}

	// Set up keyring file name
	home := deriveHome()
	kr = &fileKeyRing{fileName: filepath.Join(home, ".strongbox_keyring")}

	if *flagIdentityFile != "" {
		identityFilename = *flagIdentityFile
	} else {
		identityFilename = filepath.Join(home, defaultIdentityFilename)
	}

	// if keyring flag is set replace default keyRing
	if *flagKeyRing != "" {
		kr = &fileKeyRing{fileName: *flagKeyRing}
		// verify keyring is valid
		if err := kr.Load(); err != nil {
			log.Fatalf("unable to load keyring file:%s err:%s", *flagKeyRing, err)
		}
	}

	if *flagGenKey != "" {
		genKey(*flagGenKey)
		return
	}

	if *flagDecrypt {
		// handle recursive
		if *flagRecursive {
			var err error

			target := flag.Arg(0)
			if target == "" {
				target, err = os.Getwd()
				if err != nil {
					log.Fatalf("target path not provided and unable to get cwd err:%s", err)
				}
			}
			// for recursive decryption 'key' flag is optional but if provided
			// it should be valid and all encrypted file will be decrypted using it
			dk, err := decode([]byte(*flagKey))
			if err != nil && *flagKey != "" {
				log.Fatalf("Unable to decode given private key %v", err)
			}

			if err = recursiveDecrypt(target, dk); err != nil {
				log.Fatalln(err)
			}
			return
		}

		if *flagKey == "" {
			log.Fatalf("Must provide a `-key` when using -decrypt")
		}
		decryptCLI()
		return
	}

	if *flagRecursive {
		log.Println("-recursive flag is only supported with -decrypt")
		usage()
	}

	if *flagGenIdentity != "" {
		ageGenIdentity(*flagGenIdentity)
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

func deriveHome() string {
	// try explicitly set STRONGBOX_HOME
	if home := os.Getenv("STRONGBOX_HOME"); home != "" {
		return home
	}
	// try HOME env var
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	// Try user.Current which works in most cases, but may not work with CGO disabled.
	u, err := user.Current()
	if err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	log.Fatal("Could not find $STRONGBOX_HOME, $HOME or call os/user.Current(). Please set $STRONGBOX_HOME, $HOME or recompile with CGO enabled")
	// not reached
	return ""
}

func decryptCLI() {
	var fn string
	if flag.Arg(0) == "" {
		// no file passed, try to read stdin
		fn = "/dev/stdin"
	} else {
		fn = flag.Arg(0)
	}
	fb, err := os.ReadFile(fn)
	if err != nil {
		log.Fatalf("Unable to read file to decrypt %v", err)
	}
	dk, err := decode([]byte(*flagKey))
	if err != nil {
		log.Fatalf("Unable to decode private key %v", err)
	}
	out, err := decrypt(fb, dk)
	if err != nil {
		log.Fatalf("Unable to decrypt %v", err)
	}
	fmt.Printf("%s", out)
}	

func gitConfig() {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox.clean", "strongbox -clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.smudge", "strongbox -smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox.textconv", "strongbox -diff"},
		{"config", "--global", "--replace-all", "merge.strongbox.driver", "$HOME/strongbox_merge_driver.sh %O %A %B %L %P %S %X %Y"},
	}
	mergeDriver := `#!/usr/bin/env bash
set -o errexit -o pipefail -o nounset
common_file="$(mktemp)"
strongbox -smudge "$5" < "$1" > "$common_file"
current_file="$(mktemp)"
strongbox -smudge "$5" < "$2" > "$current_file"
other_file="$(mktemp)"
strongbox -smudge "$5" < "$3" > "$other_file"
git merge-file \
	--marker-size="$4" \
	--stdout \
	-L "$6" \
	-L "$7" \
	-L "$8" \
	"$current_file" \
	"$common_file" \
	"$other_file" \
	> "$5"
`
	if err := os.WriteFile(filepath.Join(deriveHome(), "strongbox_merge_driver.sh"), []byte(mergeDriver), 0755); err != nil {
		log.Fatalf("failed to write merge driver script %v", err)
	}
	for _, command := range args {
		cmd := exec.Command("git", command...)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(string(out))
		}
	}
	log.Println("git global configuration updated successfully")
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
	in, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	// Check the file is plaintext, if its an encrypted strongbox or age file, copy as is, and exit 0
	if bytes.HasPrefix(in, prefix) || strings.HasPrefix(string(in), armor.Header) {
		_, err = io.Copy(w, bytes.NewReader(in))
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	// File is plaintext and needs to be encrypted, get the recipient or a
	// key, fail on error
	recipient, key, err := findRecipients(filename)
	if err != nil {
		log.Fatal(err)
	}

	// found recipient file and plaintext differs from HEAD
	if recipient != nil {
		ageEncrypt(w, recipient, in, filename)
	}
	if key != nil {
		// encrypt the file, fail on error
		out, err := encrypt(in, key)
		if err != nil {
			log.Fatal(err)
		}
		// write out encrypted file, fail on error
		_, err = io.Copy(w, bytes.NewReader(out))
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Called by git on `git checkout`
func smudge(r io.Reader, w io.Writer, filename string) {
	in, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	if strings.HasPrefix(string(in), armor.Header) {
		ageDecrypt(w, in)
		return
	}
	if bytes.HasPrefix(in, prefix) {
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
		if _, err := io.Copy(w, bytes.NewReader(out)); err != nil {
			log.Println(err)
		}
		return
	}

	// file is a non-siv and non-age file, copy as is and exit
	_, err = io.Copy(w, bytes.NewReader(in))
	if err != nil {
		log.Fatal(err)
	}
}

// Finds closest age recipient or siv keyid
func findRecipients(filename string) ([]age.Recipient, []byte, error) {
	path := filepath.Dir(filename)
	for {
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			ageRecipientFilename := filepath.Join(path, recipientFilename)
			// If we found `.strongbox_recipient` - parse it and return
			if keyFile, err := os.Stat(ageRecipientFilename); err == nil && !keyFile.IsDir() {
				recipients, err := ageFileToRecipient(ageRecipientFilename)
				return recipients, nil, err
			}
			// If we found `strongbox-keyid` - get the corresponding key and return it
			keyFilename := filepath.Join(path, ".strongbox-keyid")
			if keyFile, err := os.Stat(keyFilename); err == nil && !keyFile.IsDir() {
				key, err := sivFileToKey(keyFilename)
				return nil, key, err
			}
		}
		if path == "." {
			return nil, nil, fmt.Errorf("failed to find recipient or keyid for file %s", filename)
		}
		path = filepath.Dir(path)
	}
}
