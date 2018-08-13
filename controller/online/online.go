package online

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"lib"

	"golang.org/x/crypto/ssh"
)

//Online  定义主对象
type Online struct {
	lib.Base
}

var ExpCmd = `#!/usr/bin/env expect
set username [lindex $argv 0]
set ip [lindex $argv 1]
set password [lindex $argv 2]
set cmd [lindex $argv 3]

spawn ssh ${username}@${ip} "${cmd}"
set timeout 5

expect {
    -nocase "*yes/no*" {
        send "yes\n"
    }
    -nocase "*password: " {
        send "${password}\n"
    }
}
`

var ExpScp = `#!/usr/bin/env expect
set src [lindex $argv 0]
set username [lindex $argv 1]
set ip [lindex $argv 2]
set password [lindex $argv 3]
set dst [lindex $argv 4]

spawn scp -r ${src} ${username}@${ip}:${dst}
set timeout 5

expect {
    -nocase "*yes/no*" {
        send "yes\n"
    }
    -nocase "*password: " {
        send "${password}\n"
    }
}
`

func SSHCommand(client *ssh.Client, commands []string) (output string, err error) {
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	command := strings.Join(commands, " && ")
	_output, err := session.CombinedOutput(command)
	if err != nil {
		output = string(_output)
		return
	}

	output = string(_output)
	return
}

func SSHScp(client *ssh.Client, data []byte, file string) (output string, err error) {
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	workdir, filename := filepath.Split(file)

	go func() {
		stdWrite, _ := session.StdinPipe()
		defer stdWrite.Close()

		fmt.Fprintln(stdWrite, "C0744", len(data), filename)
		stdWrite.Write(data)
		stdWrite.Write([]byte("\x00"))
	}()

	command := fmt.Sprintf("scp -t %s", workdir)
	_output, err := session.CombinedOutput(command)
	if err != nil {
		output = string(_output)
		return
	}

	output = string(_output)

	return
}

func GetAuthMethod(pwd string) (authMethod ssh.AuthMethod, err error) {
	if pwd != "" {
		authMethod = ssh.Password(pwd)
	} else {
		f := filepath.Join(os.Getenv("HOME"), ".ssh/id_rsa")
		buffer, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}

		key, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			return nil, err
		}
		authMethod = ssh.PublicKeys(key)
	}

	return
}
