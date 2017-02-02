package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-tty"
	"github.com/mitchellh/go-homedir"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	user        = flag.String("u", "", "user")
	password    = flag.String("p", "", "password")
	askPassword = flag.Bool("w", false, "ask password")
	privateKey  = flag.String("f", "", "private key")
	port        = flag.Int("P", 22, "port")
	proxy       = flag.String("x", "", "proxy server")
	timeout     = flag.Duration("T", 0*time.Second, "timeout")
	openPTY     = flag.Bool("o", false, "open pty")
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

	sshsock := os.ExpandEnv("$SSH_AUTH_SOCK")
	if sshsock != "" {
		addr, _ := net.ResolveUnixAddr("unix", sshsock)
		agentConn, _ := net.DialUnix("unix", nil, addr)
		ag := agent.NewClient(agentConn)
		authMethods = append(authMethods, ssh.PublicKeysCallback(ag.Signers))
	}
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
		User:    *user,
		Auth:    authMethods,
		Timeout: 10 * time.Second,
	}

	hostport := fmt.Sprintf("%s:%d", flag.Arg(0), *port)

	var conn *ssh.Client
	var err error

	if *proxy != "" {
		proxy_url, err := url.Parse(*proxy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		tcp, err := net.Dial("tcp", proxy_url.Host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		connReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Path: hostport},
			Host:   hostport,
			Header: make(http.Header),
		}
		connReq.Write(tcp)
		resp, err := http.ReadResponse(bufio.NewReader(tcp), connReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		defer resp.Body.Close()
		tcp = tls.Client(tcp, &tls.Config{InsecureSkipVerify: true})

		c, chans, reqs, err := ssh.NewClientConn(tcp, hostport, config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		conn = ssh.NewClient(c, chans, reqs)
	} else {
		conn, err = ssh.Dial("tcp", hostport, config)
	}

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

	if *openPTY {
		session.Stdout = colorable.NewColorableStdout()
		session.Stderr = colorable.NewColorableStderr()
		w, err := session.StdinPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create pipe: %v\n", err)
			return 1
		}
		if *openPTY {
			err = session.RequestPty("vt100", 25, 80, ssh.TerminalModes{
				ssh.ECHO:  0,
				ssh.IGNCR: 1,
			})
			if err != nil {
				fmt.Fprint(os.Stderr, err)
				return 1
			}
		}
		c := make(chan os.Signal, 10)
		defer close(c)
		signal.Notify(c, os.Interrupt)
		go func() {
			for {
				if _, ok := <-c; !ok {
					break
				}
				session.Signal(ssh.SIGINT)
			}
		}()
		err = session.Shell()
		io.Copy(w, os.Stdin)
	} else {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin
		err = session.Run(strings.Join(flag.Args()[1:], " "))
	}
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
