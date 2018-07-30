package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

	sb := Strongbox{
		keyring:   &fileKeyRing{fileName: filepath.Join(getHome(), ".strongbox_keyring")},
		keyLoader: loadKey,
	}

	app.Commands = []cli.Command{
		{
			Name:        "git-config",
			Description: "Configure git for strongbox use",
			Action:      sb.commandGitConfig,
		},
		{
			Name:        "gen-key",
			Description: "Generate a new key and add it to your strongbox keyring",
			Action:      sb.commandGenKey,
		},
		{
			Name:        "decrypt",
			Description: "Decrypt single resource",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key",
					Usage: "Private key",
				},
			},
			Action: sb.commandDecrypt,
		},

		{
			Name:        "clean",
			Description: "intended to be called internally by git",
			Action:      sb.commandClean,
		},
		{
			Name:        "smudge",
			Description: "intended to be called internally by git",
			Action:      sb.commandSmudge,
		},
		{
			Name:        "diff",
			Description: "intended to be called internally by git",
			Action:      sb.commandDiff,
		},

		{
			Name:        "version",
			Description: "Print the application version and exit",
			Action: func(c *cli.Context) (err error) {
				fmt.Println(version)
				return
			},
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
