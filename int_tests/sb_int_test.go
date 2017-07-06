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

func TestMain(m *testing.M) {
	cmd := exec.Command(
		"strongbox",
		"install",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(out))
	}
	//
	cmd = exec.Command(
		"strongbox",
		"gen-key",
		"test00",
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(out))
	}
	//
	cmd = exec.Command(
		"git", "config", "--global", "user.email", "\"you@example.com\"",
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(out))
	}
	//
	cmd = exec.Command(
		"git", "config", "--global", "user.name", "\"test\"",
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(string(out))
	}

	os.Exit(m.Run())
}

func TestSimpleEnc(t *testing.T) {
	cmd := exec.Command(
		"mkdir",
		"/test-proj",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}

	//
	cmd = exec.Command(
		"git",
		"init",
	)
	cmd.Dir = "/test-proj"
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}

	err = ioutil.WriteFile("/test-proj/.gitattributes", []byte("secret filter=strongbox diff=strongbox"), 0644)
	if err != nil {
		t.Fatal(string(out))
	}

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

	err = ioutil.WriteFile("/test-proj/.strongbox-keyid", []byte(keyId), 0644)
	if err != nil {
		t.Fatal(string(out))
	}

	err = ioutil.WriteFile("/test-proj/secret", []byte("secret123"), 0644)
	if err != nil {
		t.Fatal(string(out))
	}

	//
	cmd = exec.Command(
		"git",
		"add",
		".",
	)
	cmd.Dir = "/test-proj"
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	//
	cmd = exec.Command(
		"git",
		"commit",
		"-m",
		"\"first commit\"",
	)
	cmd.Dir = "/test-proj"
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	//
	cmd = exec.Command(
		"git",
		"show",
	)
	cmd.Dir = "/test-proj"
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	assert.Contains(t, string(out), "secret123", "no plaintext")
}
