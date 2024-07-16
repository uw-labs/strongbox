package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	recipientFilename       = ".strongbox_recipient"
	defaultIdentityFilename = ".strongbox_identity"
)

func ageGenIdentity(desc string) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	fmt.Printf("public key: %s\n", identity.Recipient().String())

	f, err := os.OpenFile(*flagIdentityFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

func ageFileToRecipient(filename string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	publicKeys, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(publicKeys, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		recipient, err := age.ParseX25519Recipient(string(line))
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func ageEncrypt(w io.Writer, r []age.Recipient, in []byte, f string) {
	// We have to do check the following because age's encryption is non
	// deterministic
	//
	// if there's no difference between the decrypted version of the file
	// at HEAD and the new contents AND file's recipient hasn't changed, do
	// not re-encrypt
	if agePlaintextEqual(in, f) && !ageRecipientChanged(f) {
		fah := ageFileAtHEAD(f)
		if _, err := io.Copy(w, bytes.NewReader(fah)); err != nil {
			log.Fatal(err)
		}
		return
	}

	armorWriter := armor.NewWriter(w)
	wc, err := age.Encrypt(armorWriter, r...)
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

func ageDecrypt(w io.Writer, in []byte) {
	identityFile, err := os.Open(*flagIdentityFile)
	if err != nil {
		log.Fatalf("Failed to open private keys file: %v", err)
	}
	defer identityFile.Close()
	identities, err := age.ParseIdentities(identityFile)
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

func agePlaintextEqual(in []byte, f string) bool {
	command := []string{"cat-file", "-e", fmt.Sprintf("HEAD:%s", f)}
	cmd := exec.Command("git", command...)
	// if git cat-file -e fails, then the file doesn't exist at HEAD, so it's new,
	// meaning we need to encrypt it for the first time
	if _, err := cmd.CombinedOutput(); err != nil {
		return false
	}

	fileAtHEAD := ageFileAtHEAD(f)
	if !strings.HasPrefix(string(fileAtHEAD), armor.Header) {
		log.Printf("Expect age header: command=%v filename=%s blob=%s", command, f, string(fileAtHEAD))
		return false
	}
	var plaintext bytes.Buffer
	ageDecrypt(&plaintext, fileAtHEAD)
	return bytes.Equal(plaintext.Bytes(), in)
}

func ageFileAtHEAD(f string) []byte {
	command := []string{"cat-file", "-p", fmt.Sprintf("HEAD:%s", f)}
	cmd := exec.Command("git", command...)
	fileAtHEAD, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	return fileAtHEAD
}

func ageRecipientChanged(filename string) bool {
	path := filepath.Dir(filename)
	for {
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			ageRecipientFilename := filepath.Join(path, recipientFilename)
			// If we found `.strongbox_recipient` - compare it with HEAD version
			if keyFile, err := os.Stat(ageRecipientFilename); err == nil && !keyFile.IsDir() {
				fah := ageFileAtHEAD(ageRecipientFilename)
				fod, err := os.ReadFile(ageRecipientFilename)
				if err != nil {
					log.Fatalf("Failed to open private keys file: %v", err)
				}
				return !bytes.Equal(fah, fod)
			}
		}
		if path == "." {
			break
		}
		path = filepath.Dir(path)
	}

	return false
}
