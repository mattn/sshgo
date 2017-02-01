# sshgo

implementation of ssh client

## Usage

```
Usage of sshgo:
  -P int
    	port (default 22)
  -f string
    	private key
  -p string
    	password
  -u string
    	user
```

## Warning

Be careful to use this. The command-line arguments with passing password/passphrase is dangerous. Anyone can steel your password.

## Installation

```
$ go get github.com/mattn/sshgo
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
