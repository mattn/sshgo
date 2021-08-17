package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-runewidth"
	"github.com/mattn/go-tty"
	"github.com/mitchellh/go-homedir"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
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
	defer t.Close()
	fmt.Print(prompt)
	defer t.Output().WriteString("\r" + strings.Repeat(" ", runewidth.StringWidth(prompt)) + "\r")
	return t.ReadPasswordClear()
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

	host := flag.Arg(0)
	if *user == "" {
		if strings.Contains(host, "@") {
			tok := strings.Split(host, "@")
			if len(tok) != 2 {
				fmt.Fprintln(os.Stderr, "invalid hostname")
				return 1
			}
			*user, host = tok[0], tok[1]
			if h, p, err := net.SplitHostPort(host); err == nil {
				host = h
				if pn, err := strconv.ParseUint(p, 10, 64); err == nil {
					*port = int(pn)
				}
			}
		} else {
			if runtime.GOOS == "windows" {
				*user = os.Getenv("USERNAME")
			} else {
				*user = os.Getenv("USER")
			}
		}
	}

	if flag.NArg() == 1 {
		*openPTY = true
	}

	var authMethods []ssh.AuthMethod

	if *askPassword || *password != "" {
		authMethods = append(authMethods, ssh.PasswordCallback(func() (string, error) {
			if *askPassword {
				return pprompt("password: ")
			}
			return *password, nil
		}))
	}

	if *privateKey == "" || *privateKey == "none" {
		sshsock := os.ExpandEnv("$SSH_AUTH_SOCK")
		if sshsock != "" {
			addr, _ := net.ResolveUnixAddr("unix", sshsock)
			agentConn, _ := net.DialUnix("unix", nil, addr)
			ag := agent.NewClient(agentConn)
			keys, err := ag.List()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			if len(keys) > 0 {
				authMethods = append(authMethods, ssh.PublicKeysCallback(ag.Signers))
			}
		}
	}

	if *privateKey == "" {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		*privateKey = filepath.Join(home, ".ssh", "id_rsa")
	}
	if *privateKey == "none" {
		*privateKey = ""
	}

	if *privateKey != "" {
		_, err := os.Stat(*privateKey)
		if len(authMethods) == 0 && os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No such private key file: %s\n", *privateKey)
			return 1
		}
		authMethods = append(authMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			if *askPassword {
				p, err := pprompt("passphrase: ")
				if err != nil {
					return nil, err
				}
				*password = p
			}
			return getSigners(*privateKey, *password)
		}))
	}

	config := &ssh.ClientConfig{
		User:            *user,
		Auth:            authMethods,
		Timeout:         *timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	hostport := fmt.Sprintf("%s:%d", host, *port)

	var conn *ssh.Client
	var err error

	if *proxy != "" {
		proxyUrl, err := url.Parse(*proxy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		tcp, err := net.Dial("tcp", proxyUrl.Host)
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
		if proxyUrl.User != nil {
			if p, ok := proxyUrl.User.Password(); ok {
				connReq.SetBasicAuth(proxyUrl.User.Username(), p)
			}
		}
		connReq.Write(tcp)
		resp, err := http.ReadResponse(bufio.NewReader(tcp), connReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		defer resp.Body.Close()

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
		st, err := terminal.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open new session: %v\n", err)
			return 1
		}
		defer terminal.Restore(int(os.Stdin.Fd()), st)

		session.Stdin = os.Stdin
		session.Stdout = colorable.NewColorableStdout()
		session.Stderr = colorable.NewColorableStderr()
		if *openPTY {
			err = session.RequestPty("vt100", 25, 80, ssh.TerminalModes{})
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
		session.Wait()
	} else {
		session.Stdin = os.Stdin
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
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
