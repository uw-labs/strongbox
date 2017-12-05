package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	yaml "gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
)

var (
	HOME = os.Getenv("HOME")
)

func command(dir, name string, arg ...string) (out []byte, err error) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	return
}

func assertCommand(t *testing.T, dir, name string, arg ...string) (out []byte) {
	out, err := command(dir, name, arg...)
	if err != nil {
		t.Fatal(string(out))
	}
	return
}

func assertWriteFile(t *testing.T, filename string, data []byte, perm os.FileMode) {
	err := ioutil.WriteFile(filename, data, perm)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func keyIdFromKR(t *testing.T, name string) (keyId string) {
	kr := make(map[string]interface{})
	krf, err := ioutil.ReadFile(HOME + "/.strongbox_keyring")
	if err != nil {
		t.Fatal(err)
	}
	err = yaml.Unmarshal(krf, kr)
	if err != nil {
		t.Fatal(err)
	}
	kes := kr["keyentries"].([]interface{})

	for k, _ := range kes {
		desc := kes[k].(map[interface{}]interface{})["description"].(string)
		if name == desc {
			return kes[k].(map[interface{}]interface{})["key-id"].(string)
		}
	}
	t.Fatal(fmt.Sprintf("no keyId for give desc: %s", name))
	return ""
}

func TestMain(m *testing.M) {
	out, err := command("/", "git", "config", "--global", "user.email", "you@example.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "git", "config", "--global", "user.name", "test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "strongbox", "git-config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "strongbox", "gen-key", "test00")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "mkdir", HOME+"/test-proj")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command(HOME+"/test-proj", "git", "init")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestSimpleEnc(t *testing.T) {
	repoDir := HOME + "/test-proj"
	keyId := keyIdFromKR(t, "test00")
	secVal := "secret123wombat"

	ga := `secret filter=strongbox diff=strongbox
secrets/* filter=strongbox diff=strongbox`
	assertWriteFile(t, repoDir+"/.gitattributes", []byte(ga), 0644)
	assertWriteFile(t, repoDir+"/.strongbox-keyid", []byte(keyId), 0644)
	assertWriteFile(t, repoDir+"/secret", []byte(secVal), 0644)
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestSimpleEnc\"")
	ptOut, _ := command(repoDir, "git", "show")
	encOut, _ := command(repoDir, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestNestedEnc(t *testing.T) {
	repoDir := HOME + "/test-proj"
	secVal := "secret123croc"

	assertCommand(t, repoDir, "mkdir", "-p", "secrets/dir0")
	assertWriteFile(t, repoDir+"/secrets/dir0/sec0", []byte(secVal), 0644)

	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestNestedEnc\"")

	ptOut, _ := command(repoDir, "git", "show")
	encOut, _ := command(repoDir, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestMissingKey(t *testing.T) {
	repoDir := HOME + "/test-proj"
	secVal := "secret-missing-key"

	// remove the key for encryption
	assertCommand(t, "/", "mv", HOME+"/.strongbox_keyring", HOME+"/.strongbox_keyring.bkup")

	assertCommand(t, "/", "strongbox", "gen-key", "tmp")

	assertWriteFile(t, repoDir+"/secrets/sec-missing-key", []byte(secVal), 0644)
	_, err := command(repoDir, "git", "add", ".")
	assert.Error(t, err, "Should error on add attempt")

	// clean up
	assertCommand(t, "/", "mv", HOME+"/.strongbox_keyring.bkup", HOME+"/.strongbox_keyring")

	// as the correct is now present, should not error and present untracked changes
	assertCommand(t, repoDir, "git", "status")

	// remove the file
	assertCommand(t, "/", "rm", repoDir+"/secrets/sec-missing-key")
}
