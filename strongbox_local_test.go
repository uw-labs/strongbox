package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const _STRONGBOX_TEST_BINARY = "strongbox-test-bin"

var binaryBuilt = false

func ensureStrongboxBuilt(t *testing.T) {
	if !binaryBuilt {
		// build the binary once per test run
		_, err := runCmd("go", "build", "-o", _STRONGBOX_TEST_BINARY, ".")
		require.NoError(t, err)
		binaryBuilt = true
	}
}

func mustRunGitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGitCmd(dir, args...)
	require.NoError(t, err)
	return out
}

func runGitCmd(dir string, args ...string) (string, error) {
	args = append([]string{"-C", dir}, args...)
	return runCmd("git", args...)
}

func runCmd(name string, args ...string) (string, error) {
	var stdout strings.Builder
	var stderr strings.Builder

	cmd := exec.Command(name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf(
			"running '%s' failed: %w\nstderr: %s",
			strings.Join(cmd.Args, " "),
			err,
			stderr.String(),
		)
	}

	return stdout.String(), nil
}

var gitConfigured = false

func configureGit(t *testing.T, repoDir string) {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)

	// pass a rooted path (and not just ./file) so we can run it from worktrees
	testBinPath := filepath.Join(cwd, _STRONGBOX_TEST_BINARY)
	gitConfigPath := filepath.Join(cwd, "testdata", "git-test-config")

	// avoid reading any configuration files outside this repo
	// https://git-scm.com/docs/git#Documentation/git.txt-codeGITCONFIGGLOBALcode
	t.Setenv("GIT_CONFIG_GLOBAL", gitConfigPath)

	if !gitConfigured {
		// we only read from the single config file, so set some identity
		// information
		mustRunGitCmd(t, repoDir, "config", "set", "--global", "user.name", "strongbox-tester")
		mustRunGitCmd(
			t,
			repoDir,
			"config",
			"set",
			"--global",
			"user.email",
			"strongbox-tester@example.com",
		)

		// setup strongbox
		mustRunGitCmd(
			t,
			repoDir,
			"config",
			"set",
			"--global",
			"filter.strongbox.clean",
			testBinPath+" -clean %f",
		)
		mustRunGitCmd(
			t,
			repoDir,
			"config",
			"set",
			"--global",
			"filter.strongbox.smudge",
			testBinPath+" -smudge %f",
		)
		mustRunGitCmd(t, repoDir, "config", "set", "--global", "filter.strongbox.required", "true")
		mustRunGitCmd(
			t,
			repoDir,
			"config",
			"set",
			"--global",
			"diff.strongbox.textconv",
			testBinPath+" -diff",
		)
		gitConfigured = true
	}
}

func configureStrongbox(t *testing.T, repoDir string) {
	// tell strongbox to use our testing keys
	t.Setenv("STRONGBOX_HOME", filepath.Join(repoDir, "testdata"))
}

func setupWorkTree(t *testing.T, name string) string {
	t.Helper()
	worktreePath := filepath.Join(t.TempDir(), name)

	mustRunGitCmd(t, ".", "worktree", "add", "--quiet", "--detach", worktreePath)
	t.Cleanup(func() {
		// practically, this shouldn't error. But even if it does, it's not
		// a big deal: the TempDir is cleaned up at the end of testing anyway, and
		// git eventually stops tracking worktrees on paths that don't exist
		if _, err := runGitCmd(".", "worktree", "remove", "--force", worktreePath); err != nil {
			t.Logf(
				"failed to remove worktree %s (you may want to manually remove it): %v",
				worktreePath,
				err,
			)
		}
	})

	configureGit(t, worktreePath)
	configureStrongbox(t, worktreePath)

	return worktreePath
}

func TestGitIntegration_Filtering(t *testing.T) {
	ensureStrongboxBuilt(t)
	repoDir := setupWorkTree(t, t.Name())

	rawContent := "t0ps3cret\n"
	expectedEncryptedPrefix := "-----BEGIN AGE ENCRYPTED FILE-----"
	secretPath := filepath.Join("testdata", "secret-"+t.Name()+".txt")
	require.NoError(
		t,
		os.WriteFile(
			filepath.Join(repoDir, secretPath),
			[]byte(rawContent),
			0o400,
		),
	)
	mustRunGitCmd(t, repoDir, "add", secretPath)

	diff, err := runGitCmd(repoDir, "diff", "--exit-code", secretPath)
	require.NoError(
		t,
		err,
		"git detected a diff after adding the file (probably an issue with smudging and cleaning):\n%s",
		diff,
	)
	mustRunGitCmd(t, repoDir, "commit", "--message", "Add a secret")

	worktreeContent, err := os.ReadFile(filepath.Join(repoDir, secretPath))
	require.NoError(t, err)
	require.Equal(t, rawContent, string(worktreeContent), "file in worktree should be decrypted")
	require.Equal(
		t,
		expectedEncryptedPrefix,
		mustRunGitCmd(t, repoDir, "show", "HEAD:"+secretPath)[:len(expectedEncryptedPrefix)],
		"checked-in file should be encrypted",
	)
}
