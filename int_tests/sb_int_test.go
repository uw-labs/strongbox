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

const (
	HOME = "/home/test"
)

func command(t *testing.T, dir, name string, arg ...string) (out []byte) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	return
}

func commandWithError(dir, name string, arg ...string) (out []byte, err error) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	return
}

func writeFile(t *testing.T, filename string, data []byte, perm os.FileMode) {
	err := ioutil.WriteFile(filename, data, perm)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func keyIdFromKR(t *testing.T, name string) (keyId string) {
	kr := make(map[string]interface{})
	krf, err := ioutil.ReadFile("/home/test/.strongbox_keyring")
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
	command(nil, "/", "git", "config", "--global", "user.email", "\"you@example.com\"")
	command(nil, "/", "git", "config", "--global", "user.name", "\"test\"")
	command(nil, "/", "strongbox", "install")
	command(nil, "/", "strongbox", "gen-key", "test00")
	command(nil, "/", "mkdir", HOME+"/test-proj")
	command(nil, HOME+"/test-proj", "git", "init")
	os.Exit(m.Run())
}

func TestSimpleEnc(t *testing.T) {
	prjDir := HOME + "/test-proj"
	keyId := keyIdFromKR(t, "test00")
	secVal := "secret123wombat"

	ga := `secret filter=strongbox diff=strongbox
secrets/* filter=strongbox diff=strongbox`
	writeFile(t, prjDir+"/.gitattributes", []byte(ga), 0644)
	writeFile(t, prjDir+"/.strongbox-keyid", []byte(keyId), 0644)
	writeFile(t, prjDir+"/secret", []byte(secVal), 0644)
	command(t, prjDir, "git", "add", ".")
	command(t, prjDir, "git", "commit", "-m", "\"TestSimpleEnc\"")
	ptOut := command(t, prjDir, "git", "show")
	encOut := command(t, prjDir, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestNestedEnc(t *testing.T) {
	prjDir := HOME + "/test-proj"
	secVal := "secret123croc"

	command(t, prjDir, "mkdir", "-p", "secrets/dir0")
	writeFile(t, prjDir+"/secrets/dir0/sec0", []byte(secVal), 0644)

	command(t, prjDir, "git", "add", ".")
	command(t, prjDir, "git", "commit", "-m", "\"TestNestedEnc\"")

	ptOut := command(t, prjDir, "git", "show")
	encOut := command(t, prjDir, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestMissingKey(t *testing.T) {
	prjDir := HOME + "/test-proj"
	secVal := "secret-missing-key"

	// remove the key for encryption
	command(t, "/", "mv", HOME+"/.strongbox_keyring", HOME+"/.strongbox_keyring.bkup")
	command(nil, "/", "strongbox", "gen-key", "tmp")

	writeFile(t, prjDir+"/secrets/sec-missing-key", []byte(secVal), 0644)
	_, err := commandWithError(prjDir, "git", "add", ".")
	assert.Error(t, err, "Should error on add attempt")

	// clean up
	command(t, "/", "mv", HOME+"/.strongbox_keyring.bkup", HOME+"/.strongbox_keyring")

	// as the correct is now present, should not error and present untracked changes
	_, err = commandWithError(prjDir, "git", "status")
	assert.Nil(t, err)

	// remove the file
	command(t, "/", "rm", prjDir+"/secrets/sec-missing-key")
}
