package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const version = "0.1.0-dev"

var (
	errKeyNotFound = errors.New("key not found")
	prefix         = []byte("# STRONGBOX ENCRYPTED RESOURCE ;")
	defaultPrefix  = []byte("# STRONGBOX ENCRYPTED RESOURCE ; See https://github.com/uw-labs/strongbox\n")
)

// Strongbox stores application state
type Strongbox struct {
	keyring   keyRing
	keyLoader func(string, keyRing) ([]byte, error)
}

func main() {
	log.SetPrefix("strongbox: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app := cli.NewApp()
	app.Name = "strongbox"
	app.Version = version
	app.Usage = ""
	app.Description = "Encryption for git users."
	app.EnableBashCompletion = true

	sb := Strongbox{
		keyring:   &fileKeyRing{fileName: filepath.Join(getHome(), ".strongbox_keyring")},
		keyLoader: loadKey,
	}

	app.Commands = []cli.Command{
		{
			Name:   "git-config",
			Usage:  "Configure git for strongbox use",
			Action: sb.commandGitConfig,
		},
		{
			Name:   "gen-key",
			Usage:  "Generate a new key and add it to your strongbox keyring",
			Action: sb.commandGenKey,
		},
		{
			Name:  "decrypt",
			Usage: "Decrypt single resource",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key",
					Usage: "Private key",
				},
			},
			Action: sb.commandDecrypt,
		},

		{
			Name:   "clean",
			Usage:  "intended to be called internally by git",
			Action: sb.commandClean,
		},
		{
			Name:   "smudge",
			Usage:  "intended to be called internally by git",
			Action: sb.commandSmudge,
		},
		{
			Name:   "diff",
			Usage:  "intended to be called internally by git",
			Action: sb.commandDiff,
		},

		{
			Name:  "version",
			Usage: "Print the application version and exit",
			Action: func(c *cli.Context) (err error) {
				fmt.Println(version)
				return
			},
		},
		{
			Name: "completion",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "flavour",
					Usage: "shell flavour: bash or zsh",
					Value: "bash",
				},
			},
			Action: commandCompletion,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func (sb *Strongbox) commandGitConfig(c *cli.Context) (err error) {
	args := [][]string{
		{"config", "--global", "--replace-all", "filter.strongbox.clean", "strongbox clean %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.smudge", "strongbox smudge %f"},
		{"config", "--global", "--replace-all", "filter.strongbox.required", "true"},

		{"config", "--global", "--replace-all", "diff.strongbox.textconv", "strongbox diff"},
	}
	for _, command := range args {
		cmd := exec.Command("git", command...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return errors.New(string(out))
		}
	}
	log.Println("git global configuration updated successfully")

	return
}

func (sb *Strongbox) commandDecrypt(c *cli.Context) (err error) {
	if !c.IsSet("key") {
		return errors.New("decrypt requires --key to be set")
	}
	key := c.String("key")

	var input io.Reader
	if c.Args().First() == "" {
		// no file passed, try to read stdin
		input = os.Stdin
	} else {
		input, err = os.Open(c.Args().First())
		if err != nil {
			return errors.Wrap(err, "failed to open input file")
		}
	}

	contents, err := ioutil.ReadAll(input)
	if err != nil {
		return errors.Wrap(err, "failed to read input stream")
	}

	dk, err := decode([]byte(key))
	if err != nil {
		return errors.Wrap(err, "failed to decode private key")
	}

	out, err := decrypt(contents, dk)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}

	fmt.Printf("%s", out)
	return
}

func (sb *Strongbox) commandGenKey(c *cli.Context) (err error) {
	err = sb.keyring.Load()
	if err != nil && !os.IsNotExist(err) {
		return
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	keyID := sha256.Sum256(key)

	sb.keyring.AddKey(c.Args().First(), keyID[:], key)

	err = sb.keyring.Save()
	if err != nil {
		return
	}

	return
}

func (sb *Strongbox) commandClean(c *cli.Context) (err error) {
	return clean(os.Stdin, os.Stdout, c.Args().First(), sb.keyring)
}

func (sb *Strongbox) commandSmudge(c *cli.Context) (err error) {
	return smudge(os.Stdin, os.Stdout, c.Args().First(), sb.keyring)
}

func (sb *Strongbox) commandDiff(c *cli.Context) (err error) {
	return diff(c.Args().First())
}

func commandCompletion(c *cli.Context) (err error) {
	var flavour = c.String("flavour")

	resp, err := http.Get(fmt.Sprintf("https://raw.githubusercontent.com/urfave/cli/master/autocomplete/%s_autocomplete", flavour))
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return errors.Errorf("failed to get bash completion: %s", resp.Status)
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	completionFile := filepath.Join(getHome(), ".strongbox_autocomplete.sh")

	err = ioutil.WriteFile(completionFile, contents, 0700)
	if err != nil {
		return
	}

	log.Println("Successfully written", flavour, "completion to", completionFile)
	log.Println("To enable, add the following line to your .bashrc file (or equivalent)")
	log.Println("PROG=strongbox source", completionFile)

	return
}

func getHome() (home string) {
	u, err := user.Current()
	if err != nil {
		// Possibly compiled without CGO and syscall isn't implemented,
		// try to grab the environment variable
		home = os.Getenv("HOME")
		if home == "" {
			log.Fatal("Could not call os/user.Current() or find $HOME. Please recompile with CGO enabled or set $HOME")
		}
	} else {
		home = u.HomeDir
	}
	return home
}
