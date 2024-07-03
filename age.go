package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	recipientFilename       = ".strongbox_recipient"
	defaultIdentityFilename = ".strongbox_identity"
)

var (
	identityFilename string
)

func ageGenIdentity(desc string) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	fmt.Printf("public key: %s\n", identity.Recipient().String())

	f, err := os.OpenFile(identityFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	// if there's no difference between the decrypted version of the file at HEAD
	// and the new contents, then we re-use the previous version to prevent
	// unnecessary file updates
	if agePlaintextEqual(in, f) {
		fah := fileAtHEAD(f)
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
	identityFile, err := os.Open(identityFilename)
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

	fileAtHEAD := fileAtHEAD(f)
	if !strings.HasPrefix(string(fileAtHEAD), armor.Header) {
		//log.Fatalf("Expect age header: filename=%s", f)
		log.Printf("Expect age header: command=%v filename=%s blob=%s", command, f, string(fileAtHEAD))
	}
	var plaintext bytes.Buffer
	ageDecrypt(&plaintext, fileAtHEAD)
	return bytes.Equal(plaintext.Bytes(), in)
}

func fileAtHEAD(f string) []byte {
	command := []string{"cat-file", "-p", fmt.Sprintf("HEAD:%s", f)}
	cmd := exec.Command("git", command...)
	fileAtHEAD, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	return fileAtHEAD
}
