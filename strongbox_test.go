//go:build integration

package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v2"
)

var (
	HOME           = deriveHome()
	defaultRepoDir = "/tmp/test-proj/"
	defaultBranch  = "main"
)

func command(dir, name string, arg ...string) (out []byte, err error) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	fmt.Println(string(out))
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
	err := os.WriteFile(filename, data, perm)
	if err != nil {
		t.Fatal(err)
	}
}

func assertReadFile(t *testing.T, filename string) string {
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func keysFromKR(t *testing.T, name string) (key, keyID string) {
	kr := make(map[string]interface{})
	krf, err := os.ReadFile(HOME + "/.strongbox_keyring")
	if err != nil {
		t.Fatal(err)
	}
	err = yaml.Unmarshal(krf, kr)
	if err != nil {
		t.Fatal(err)
	}
	kes := kr["keyentries"].([]interface{})

	for k := range kes {
		desc := kes[k].(map[interface{}]interface{})["description"].(string)
		if name == desc {
			return kes[k].(map[interface{}]interface{})["key"].(string),
				kes[k].(map[interface{}]interface{})["key-id"].(string)
		}
	}
	t.Fatal(fmt.Sprintf("no keyId for give desc: %s", name))
	return "", ""
}

func recipients() [][][]byte {
	f, _ := os.ReadFile(HOME + "/.strongbox_identity")
	r := regexp.MustCompile(`(?m)^.*public key.*(age.*)$`)
	return r.FindAllSubmatch(f, -1)
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
	out, err = command("/", "strongbox", "-git-config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "strongbox", "-gen-key", "test00")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "strongbox", "-gen-identity", "ident1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "strongbox", "-gen-identity", "ident2")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command("/", "mkdir", defaultRepoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command(defaultRepoDir, "git", "config", "--global", "init.defaultBranch", defaultBranch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	out, err = command(defaultRepoDir, "git", "init")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", string(out))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestMergeDriverMerge(t *testing.T) {
	repoDir := defaultRepoDir
	secDir := "secrets/dir0/"
	secFileName := "sec0"
	secFilePath := secDir + secFileName
	secVal := "secret123wallaby"
	_, keyID := keysFromKR(t, "test00")
	ga := "secrets/* filter=strongbox diff=strongbox merge=strongbox"

	assertWriteFile(t, repoDir+"/.gitattributes", []byte(ga), 0644)
	assertWriteFile(t, repoDir+"/.strongbox-keyid", []byte(keyID), 0644)
	assertCommand(t, repoDir, "mkdir", "-p", secDir)
	assertWriteFile(t, repoDir+secFilePath, []byte(secVal), 0644)
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestMergeDriverMerge\"")

	branches := []string{"temp1", "temp2"}
	for i, branch := range branches {
		if i != 0 {
			assertCommand(t, repoDir, "git", "checkout", defaultBranch)
		}
		assertCommand(t, repoDir, "git", "checkout", "-b", branch)
		assertWriteFile(t, repoDir+secFilePath, []byte(secVal+branch), 0644)
		assertCommand(t, repoDir, "git", "add", ".")
		assertCommand(t, repoDir, "git", "commit", "-m", "\"TestMergeDiff "+branch+"\"")
		if i == len(branches)-1 {
			command(repoDir, "git", "merge", "temp1")
		}
	}

	out, _ := command(repoDir, "cat", secFilePath)
	assert.NotContains(t, string(out), "STRONGBOX ENCRYPTED RESOURCE")
	assert.Contains(t, string(out), "<<<<<<< HEAD\n"+secVal+branches[1]+"\n=======\n"+secVal+branches[0]+"\n>>>>>>> "+branches[0]+"\n")
	command(repoDir, "git", "merge", "--abort")
	command(repoDir, "git", "checkout", defaultBranch)
	for _, branch := range branches {
		command(repoDir, "git", "branch", "-D", branch)
	}
}

func TestMergeDriverRebase(t *testing.T) {
	repoDir := defaultRepoDir
	secDir := "secrets/dir0/"
	secFileName := "sec0"
	secFilePath := secDir + secFileName
	secVal := "secret123raccoon"
	commitMsg := "TestMergeDriverRebase"
	_, keyID := keysFromKR(t, "test00")
	ga := "secrets/* filter=strongbox diff=strongbox merge=strongbox"

	assertWriteFile(t, repoDir+"/.gitattributes", []byte(ga), 0644)
	assertWriteFile(t, repoDir+"/.strongbox-keyid", []byte(keyID), 0644)
	assertCommand(t, repoDir, "mkdir", "-p", secDir)
	assertWriteFile(t, repoDir+secFilePath, []byte(secVal), 0644)
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\""+commitMsg+"\"")

	commitHash := ""
	branches := []string{"temp1", "temp2"}
	for i, branch := range branches {
		branchCommitMsg := commitMsg + " " + branch
		if i != 0 {
			assertCommand(t, repoDir, "git", "checkout", defaultBranch)
		}
		assertCommand(t, repoDir, "git", "checkout", "-b", branch)
		assertWriteFile(t, repoDir+secFilePath, []byte(secVal+branch), 0644)
		assertCommand(t, repoDir, "git", "add", ".")
		assertCommand(t, repoDir, "git", "commit", "-m", "\""+branchCommitMsg+"\"")
		if i == len(branches)-1 {
			assertCommand(t, repoDir, "git", "checkout", branches[i-1])
			commitHashBytes := assertCommand(t, repoDir, "git", "rev-parse", "--short", "HEAD")
			commitHash = strings.TrimSuffix(string(commitHashBytes), "\n")
			fmt.Println(commitHash)
			command(repoDir, "git", "rebase", branch)
		}
	}

	out, _ := command(repoDir, "cat", secFilePath)
	assert.NotContains(t, string(out), "STRONGBOX ENCRYPTED RESOURCE")
	assert.Contains(t, string(out), "<<<<<<< HEAD\n"+secVal+branches[1]+"\n=======\n"+secVal+branches[0]+"\n>>>>>>> "+commitHash+" (\""+commitMsg+" "+branches[0]+"\")"+"\n")
	command(repoDir, "git", "rebase", "--abort")
	command(repoDir, "git", "checkout", defaultBranch)
	for _, branch := range branches {
		command(repoDir, "git", "branch", "-D", branch)
	}
}

func TestSimpleEnc(t *testing.T) {
	repoDir := defaultRepoDir
	_, keyID := keysFromKR(t, "test00")
	secVal := "secret123wombat"

	ga := `secret filter=strongbox diff=strongbox
secrets/* filter=strongbox diff=strongbox`
	assertWriteFile(t, repoDir+"/.gitattributes", []byte(ga), 0644)
	assertWriteFile(t, repoDir+"/.strongbox-keyid", []byte(keyID), 0644)
	assertWriteFile(t, repoDir+"/secret", []byte(secVal), 0644)
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestSimpleEnc\"")
	ptOut, _ := command(repoDir, "git", "show", "--", "secret")
	encOut, _ := command(repoDir, "git", "show", "HEAD:secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "STRONGBOX ENCRYPTED RESOURCE", "no plaintext")
}

func TestNestedEnc(t *testing.T) {
	repoDir := defaultRepoDir
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
	repoDir := defaultRepoDir
	secVal := "secret-missing-key"

	// remove the key for encryption
	assertCommand(t, "/", "mv", HOME+"/.strongbox_keyring", HOME+"/.strongbox_keyring.bkup")

	assertCommand(t, "/", "strongbox", "-gen-key", "tmp")

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

func TestRecursiveDecryption(t *testing.T) {
	repoDir := HOME + "/test-rec-dec"

	assertCommand(t, "/", "mkdir", "-p", repoDir+"/secrets/")
	assertCommand(t, "/", "mkdir", "-p", repoDir+"/app/secrets/")

	assertCommand(t, repoDir, "git", "init")

	// generate new private keys
	assertCommand(t, "/", "strongbox", "-gen-key", "rec-dec-01")
	assertCommand(t, "/", "strongbox", "-gen-key", "rec-dec-02")

	pKey1, keyID1 := keysFromKR(t, "rec-dec-01")
	pKey2, keyID2 := keysFromKR(t, "rec-dec-02")

	secVal := "secret123wombat"

	ga := `secret filter=strongbox diff=strongbox
secrets/* filter=strongbox diff=strongbox
*/secrets/* filter=strongbox diff=strongbox`

	// setup root keyID and nested app folder with different keyID
	assertWriteFile(t, repoDir+"/.gitattributes", []byte(ga), 0644)
	assertWriteFile(t, repoDir+"/.strongbox-keyid", []byte(keyID1), 0644)
	assertWriteFile(t, repoDir+"/app/.strongbox-keyid", []byte(keyID2), 0644)

	// Write plan secrets
	assertWriteFile(t, repoDir+"/secret", []byte(secVal+"01"), 0644)
	assertWriteFile(t, repoDir+"/secrets/s2", []byte(secVal+"02"), 0644)
	assertWriteFile(t, repoDir+"/app/secrets/s3", []byte(secVal+"03"), 0644)

	// set test dir as Home because git command will use default strongbox key
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestSimpleEnc\"")

	// Make sure files are encrypted
	ptOut01, _ := command(repoDir, "git", "show", "--", "secret")
	encOut01, _ := command(repoDir, "git", "show", "HEAD:secret")
	assert.Contains(t, string(ptOut01), secVal+"01", "should be in plain text")
	assert.Contains(t, string(encOut01), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")

	ptOut02, _ := command(repoDir, "git", "show", "--", "secrets/s2")
	encOut02, _ := command(repoDir, "git", "show", "HEAD:secrets/s2")
	assert.Contains(t, string(ptOut02), secVal+"02", "should be in plain text")
	assert.Contains(t, string(encOut02), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")

	ptOut03, _ := command(repoDir, "git", "show", "--", "app/secrets/s3")
	encOut03, _ := command(repoDir, "git", "show", "HEAD:app/secrets/s3")
	assert.Contains(t, string(ptOut03), secVal+"03", "should be in plain text")
	assert.Contains(t, string(encOut03), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")

	// TEST 1 (using default keyring file location)
	//override local file with encrypted content
	assertWriteFile(t, repoDir+"/secret", encOut01, 0644)
	assertWriteFile(t, repoDir+"/secrets/s2", encOut02, 0644)
	assertWriteFile(t, repoDir+"/app/secrets/s3", encOut03, 0644)

	// run command from the root of the target folder without path arg
	assertCommand(t, repoDir, "strongbox", "-decrypt", "-recursive")

	// make sure all files are decrypted
	assert.Contains(t, assertReadFile(t, repoDir+"/secret"), secVal+"01", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/secrets/s2"), secVal+"02", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/app/secrets/s3"), secVal+"03", "should be in plain text")

	// TEST 2 (using custom keyring file location)
	// override local file with encrypted content
	assertWriteFile(t, repoDir+"/secret", encOut01, 0644)
	assertWriteFile(t, repoDir+"/secrets/s2", encOut02, 0644)
	assertWriteFile(t, repoDir+"/app/secrets/s3", encOut03, 0644)

	keyRingPath := repoDir + "/.keyring"
	// move keyring file
	assertCommand(t, "/", "mv", HOME+"/.strongbox_keyring", keyRingPath)
	// run command from outside of the target folder
	assertCommand(t, "/", "strongbox", "-keyring", keyRingPath, "-decrypt", "-recursive", repoDir)

	// make sure all files are decrypted
	assert.Contains(t, assertReadFile(t, repoDir+"/secret"), secVal+"01", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/secrets/s2"), secVal+"02", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/app/secrets/s3"), secVal+"03", "should be in plain text")

	// TEST 3.1 (using given private key)
	// override local file with encrypted content
	assertWriteFile(t, repoDir+"/secret", encOut01, 0644)
	assertWriteFile(t, repoDir+"/secrets/s2", encOut02, 0644)
	assertWriteFile(t, repoDir+"/app/secrets/s3", encOut03, 0644)

	//since rec-dec-01 is not used to encrypt app folders secret so expect error
	command(repoDir, "strongbox", "-key", pKey1, "-decrypt", "-recursive", ".")

	assert.Contains(t, assertReadFile(t, repoDir+"/secret"), secVal+"01", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/secrets/s2"), secVal+"02", "should be in plain text")
	assert.Contains(t, assertReadFile(t, repoDir+"/app/secrets/s3"), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")

	// TEST 3.2 (using custom keyring file location)
	// override local file with encrypted content
	assertWriteFile(t, repoDir+"/secret", encOut01, 0644)
	assertWriteFile(t, repoDir+"/secrets/s2", encOut02, 0644)
	assertWriteFile(t, repoDir+"/app/secrets/s3", encOut03, 0644)

	//since rec-dec-02 is not used to encrypt root folders secrets so expect error
	command(repoDir, "strongbox", "-key", pKey2, "-decrypt", "-recursive", ".")

	assert.Contains(t, assertReadFile(t, repoDir+"/secret"), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")
	assert.Contains(t, assertReadFile(t, repoDir+"/secrets/s2"), "STRONGBOX ENCRYPTED RESOURCE", "should be encrypted")
	assert.Contains(t, assertReadFile(t, repoDir+"/app/secrets/s3"), secVal+"03", "should be in plain text")
}

func TestAgeEnc(t *testing.T) {
	repoDir := defaultRepoDir
	secVal := "age_secret1"

	assertCommand(t, repoDir, "mkdir", "-p", "age/secrets")

	assertWriteFile(t, repoDir+"/age/.gitattributes", []byte(`secrets/* filter=strongbox diff=strongbox`), 0644)

	assertWriteFile(t, repoDir+"/.strongbox_recipient", recipients()[0][1], 0644)

	assertWriteFile(t, repoDir+"/age/secrets/secret", []byte(secVal), 0644)

	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestAgeEnc\"")

	ptOut, _ := command(repoDir, "git", "show")
	encOut, _ := command(repoDir, "git", "show", "HEAD:age/secrets/secret")

	assert.Contains(t, string(ptOut), secVal, "no plaintext")
	assert.Contains(t, string(encOut), "-----BEGIN AGE ENCRYPTED FILE-----", "missing age header")
}

func TestAgeKeyUpdate(t *testing.T) {
	repoDir := defaultRepoDir

	// update recipient
	assertWriteFile(t, repoDir+"/.strongbox_recipient", recipients()[1][1], 0644)

	assertCommand(t, repoDir, "touch", "age/secrets/secret")
	assertCommand(t, repoDir, "git", "add", ".")
	assertCommand(t, repoDir, "git", "commit", "-m", "\"TestAgeKeyUpdate\"")

	encOut, _ := command(repoDir, "git", "show", "HEAD:age/secrets/secret")
	encOutPrevCommit, _ := command(repoDir, "git", "show", "HEAD^1:age/secrets/secret")

	assert.Contains(t, string(encOut), "-----BEGIN AGE ENCRYPTED FILE-----", "missing age header")
	assert.NotEqual(t, string(encOut), string(encOutPrevCommit), "cipher text hasn't changed")
}

func TestAgeSimulateDeterministic(t *testing.T) {
	repoDir := defaultRepoDir

	assertCommand(t, repoDir, "touch", "age/secrets/secret")

	status, _ := command(repoDir, "git", "status")

	assert.NotContains(t, string(status), "age/secrets/secret", "secret file showing up in diff")
}
