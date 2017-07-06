package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"testing"

	yaml "gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
)

func setUpCommand(dir, name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(out))
	}
}

func testWriteFile(filename string, data []byte, perm os.FileMode, t *testing.T) {
	err := ioutil.WriteFile(filename, data, perm)
	if err != nil {
		t.Fatal(err)
	}
}

func testCommand(t *testing.T, dir, name string, arg ...string) (out []byte) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	return
}

func TestMain(m *testing.M) {
	setUpCommand("/", "strongbox", "install")
	setUpCommand("/", "strongbox", "gen-key", "test00")
	setUpCommand("/", "git", "config", "--global", "user.email", "\"you@example.com\"")
	setUpCommand("/", "git", "config", "--global", "user.name", "\"test\"")
	setUpCommand("/", "mkdir", "/test-proj")
	setUpCommand("/test-proj", "git", "init")
	os.Exit(m.Run())
}

func TestSimpleEnc(t *testing.T) {
	assert := assert.New(t)

	testWriteFile("/test-proj/.gitattributes", []byte("secret filter=strongbox diff=strongbox"), 0644, t)

	// get key-id
	kr := make(map[string]interface{})
	krf, err := ioutil.ReadFile("/home/test/.strongbox_keyring")
	if err != nil {
		t.Fatal(err)
	}
	err = yaml.Unmarshal(krf, kr)
	if err != nil {
		t.Fatal(err)
	}
	keyId := kr["keyentries"].([]interface{})[0].(map[interface{}]interface{})["key-id"].(string)

	testWriteFile("/test-proj/.strongbox-keyid", []byte(keyId), 0644, t)
	testWriteFile("/test-proj/secret", []byte("secret123"), 0644, t)
	testCommand(t, "/test-proj", "git", "add", ".")
	testCommand(t, "/test-proj", "git", "commit", "-m", "\"first commit\"")
	out := testCommand(t, "/test-proj", "git", "show")

	assert.Contains(string(out), "secret123", "no plaintext")
}
