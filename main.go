package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-tty"
	"github.com/mitchellh/go-homedir"

	"golang.org/x/crypto/ssh"
)

var (
	user        = flag.String("u", "", "user")
	password    = flag.String("p", "", "password")
	askPassword = flag.Bool("w", false, "ask password")
	privateKey  = flag.String("f", "", "private key")
	port        = flag.Int("P", 22, "port")
	timeout     = flag.Duration("T", 0*time.Second, "timeout")
)

func pprompt(prompt string) (string, error) {
	t, err := tty.Open()
	if err != nil {
		return "", err
	}
	fmt.Print(prompt)
	return t.ReadPassword()
}

func getSigners(keyfile string, password string) ([]ssh.Signer, error) {
	buf, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(buf)
	if x509.IsEncryptedPEMBlock(b) {
		buf, err = x509.DecryptPEMBlock(b, []byte(password))
		if err != nil {
			return nil, err
		}
		pk, err := x509.ParsePKCS1PrivateKey(buf)
		if err != nil {
			return nil, err
		}
		k, err := ssh.NewSignerFromKey(pk)
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{k}, nil
	}
	k, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return []ssh.Signer{k}, nil
}

func run() int {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return 2
	}
	if *privateKey == "" {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		*privateKey = filepath.Join(home, ".ssh", "id_rsa")
	}
	if *user == "" {
		if runtime.GOOS == "windows" {
			*user = os.Getenv("USERNAME")
		} else {
			*user = os.Getenv("USER")
		}
	}

	var authMethods []ssh.AuthMethod

	authMethods = append(authMethods, ssh.PasswordCallback(func() (string, error) {
		if *askPassword {
			return pprompt("password: ")
		}
		return *password, nil
	}))
	if *privateKey != "" {
		authMethods = append(authMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			if *askPassword {
				p, err := pprompt("password: ")
				if err != nil {
					return nil, err
				}
				*password = p
			}
			return getSigners(*privateKey, *password)
		}))
	}

	config := &ssh.ClientConfig{
		User: *user,
		Auth: authMethods,
	}

	hostport := fmt.Sprintf("%s:%d", flag.Arg(0), *port)
	conn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect %v: %v\n", hostport, err)
		return 1
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
		return 1
	}
	defer session.Close()

	if *timeout > 0 {
		go func() {
			time.Sleep(*timeout)
			conn.Close()
		}()
	}

	session.Stdout = colorable.NewColorableStdout()
	session.Stderr = colorable.NewColorableStderr()
	session.Stdin = os.Stdin
	err = session.RequestPty("xterm", 25, 80, ssh.TerminalModes{})
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}
	err = session.Run(strings.Join(flag.Args()[1:], " "))
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		if ee, ok := err.(*ssh.ExitError); ok {
			return ee.ExitStatus()
		}
		return 1
	}
	return 0
}

func main() {
	os.Exit(run())
}
