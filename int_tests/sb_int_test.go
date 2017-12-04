package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"testing"

	yaml "gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
)

var testRepo = "/tmp/strongbox-test." + strconv.Itoa(os.Getpid())

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

func keyIdFromKR(t *testing.T, name string) (keyId string) {
	kr := make(map[string]interface{})
	krf, err := ioutil.ReadFile(os.Getenv("HOME") + "/.strongbox_keyring")
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
	setUpCommand("/", "strongbox", "git-config")
	setUpCommand("/", "strongbox", "gen-key", "test00")
	setUpCommand("/", "mkdir", testRepo)
	setUpCommand(testRepo, "git", "init")
	setUpCommand(testRepo, "git", "config", "user.email", "testuser@example.com")
	setUpCommand(testRepo, "git", "config", "user.name", "testuser")
	os.Exit(m.Run())
}

func TestSimpleEnc(t *testing.T) {
	keyId := keyIdFromKR(t, "test00")
	secVal := "secret123wombat"

	ga := `secret filter=strongbox diff=strongbox
sb-secrets/* filter=strongbox diff=strongbox`
	testWriteFile(testRepo+"/.gitattributes", []byte(ga), 0644, t)
	testWriteFile(testRepo+"/.strongbox-keyid", []byte(keyId), 0644, t)
	testWriteFile(testRepo+"/secret", []byte(secVal), 0644, t)
	testCommand(t, testRepo, "git", "add", ".")
	testCommand(t, testRepo, "git", "commit", "-m", "\"TestSimpleEnc\"")
	ptOut := testCommand(t, testRepo, "git", "show")
	encOut := testCommand(t, testRepo, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestNestedEnc(t *testing.T) {
	secVal := "secret123croc"

	testCommand(t, testRepo, "mkdir", "-p", "sb-secrets/dir0")
	testWriteFile(testRepo+"/sb-secrets/dir0/sec0", []byte(secVal), 0644, t)

	testCommand(t, testRepo, "git", "add", ".")
	testCommand(t, testRepo, "git", "commit", "-m", "\"TestNestedEnc\"")

	ptOut := testCommand(t, testRepo, "git", "show")
	encOut := testCommand(t, testRepo, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}
