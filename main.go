package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"

	"golang.org/x/crypto/ssh"
)

var (
	user       = flag.String("u", "", "user")
	password   = flag.String("p", "", "password")
	privateKey = flag.String("f", "", "private key")
	port       = flag.Int("P", 22, "port")
)

func getSigner(keyPath string) (key ssh.Signer, err error) {
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	if keyPath == "" {
		keyPath = filepath.Join(home, ".ssh", "id_rsa")
	}
	buf, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(buf)
	if x509.IsEncryptedPEMBlock(b) {
		buf, err = x509.DecryptPEMBlock(b, []byte(*password))
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
		return k, nil
	}
	k, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func run() int {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return 2
	}

	var authMethods []ssh.AuthMethod

	authMethods = append(authMethods, ssh.Password(*password))
	if *privateKey != "" {
		signer, err := getSigner(*privateKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:    *user,
		Auth:    authMethods,
		Timeout: 5 * time.Second,
	}

	hostport := fmt.Sprintf("%s:%d", flag.Arg(0), *port)
	conn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect %v: %v", hostport, err)
		return 1
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open new session: %v", err)
		return 1
	}
	defer session.Close()

	go func() {
		time.Sleep(5 * time.Second)
		conn.Close()
	}()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
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
