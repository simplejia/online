package online

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lib"

	"github.com/simplejia/clog/api"
	"golang.org/x/crypto/ssh"
)

// TransFileReq 接受值
type TransFileReq struct {
	Code        string   `json:"code"` // gzip, zip, tar, tgz, tar.gz
	TargetHosts []string `json:"target_hosts"`
	TargetDir   string   `json:"target_dir"`
	TargetFile  string   `json:"target_file"`
	TargetPort  int      `json:"target_port"`
	TargetUser  string   `json:"target_user"`
	TargetPWD   string   `json:"target_pwd"`
	Raw         string   `json:"raw"` // base64 encoding
}

// Regular 用于参数校验
func (transFileReq *TransFileReq) Regular() (ok bool) {
	if transFileReq == nil {
		return
	}

	if len(transFileReq.TargetHosts) <= 0 {
		return
	}

	if transFileReq.TargetDir == "" {
		return
	}

	if transFileReq.TargetPort <= 0 {
		transFileReq.TargetPort = 22
	}

	if transFileReq.TargetUser == "" {
		return
	}

	if transFileReq.Raw == "" {
		return
	}

	code := strings.ToLower(transFileReq.Code)
	switch code {
	case "", "gzip", "zip", "tar", "tgz", "tar.gz":
		transFileReq.Code = code
	default:
		return
	}

	if code == "" && transFileReq.TargetFile == "" {
		return
	}

	ok = true
	return
}

// TransFile
type TransFileRsp struct {
}

// TransFile just for demo
func (online *Online) TransFile(w http.ResponseWriter, r *http.Request) {
	fun := "online.Online.TransFile"

	var transFileReq *TransFileReq
	if err := json.Unmarshal(online.ReadBody(r), &transFileReq); err != nil || !transFileReq.Regular() {
		clog.Error("%s param err: %v, req: %v", fun, err, transFileReq)
		online.ReplyFail(w, lib.CodePara)
		return
	}

	data, err := base64.StdEncoding.DecodeString(transFileReq.Raw)
	if err != nil {
		detail := "raw encoding unexpected"
		clog.Error("%s DecodeString err: %v, req: %v", fun, err, transFileReq.Raw)
		online.ReplyFailWithDetail(w, lib.CodePara, detail)
		return
	}

	authMethod, err := GetAuthMethod(transFileReq.TargetPWD)
	if err != nil {
		clog.Error("%s GetAuthMethod err: %v, req: %v", fun, err, transFileReq.TargetPWD)
		online.ReplyFailWithDetail(w, lib.CodePara, err.Error())
		return
	}

	config := &ssh.ClientConfig{
		User: transFileReq.TargetUser,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * 5,
	}

	for _, targetHost := range transFileReq.TargetHosts {
		clog.Info("%s target: %s", fun, targetHost)

		client, err := ssh.Dial(
			"tcp",
			net.JoinHostPort(targetHost, strconv.Itoa(transFileReq.TargetPort)),
			config,
		)
		if err != nil {
			clog.Error("%s ssh.Dial err: %v, req: %v", fun, err, targetHost)
			online.ReplyFail(w, lib.CodeSrv)
			return
		}
		defer client.Close()

		var commands []string

		workdir := transFileReq.TargetDir

		sourceFileTmp := fmt.Sprintf(
			"tmp_%s",
			time.Now().Format("20060102150405"),
		)
		if transFileReq.TargetFile != "" {
			sourceFileTmp = fmt.Sprintf(
				"%s_%s",
				sourceFileTmp,
				transFileReq.TargetFile,
			)
		}
		tfile := filepath.Join(workdir, sourceFileTmp)

		//文件拷贝目标主机
		if output, err := SSHScp(client, data, tfile); err != nil {
			clog.Error("%s SSHScp err: %v, req: %v, resp: %v", fun, err, tfile, output)
			online.ReplyFailWithDetail(w, lib.CodeSrv, output)
			return
		} else {
			clog.Info("%s SSHScp req: %v, resp: %v", fun, "", output)
		}

		defer func() {
			command := fmt.Sprintf(
				"[[ -e %s ]] && rm %s || true",
				tfile,
				tfile,
			)

			if output, err := SSHCommand(client, []string{command}); err != nil {
				clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
				return
			} else {
				clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
			}
		}()

		// 对目标机上文件首先进行备份，并删除过期文件(n天前)
		if transFileReq.TargetFile != "" {
			backup := fmt.Sprintf(
				"backup_%s_%s",
				time.Now().Format("20060102150405"),
				transFileReq.TargetFile,
			)
			commands = append(commands, fmt.Sprintf(
				"cd %s && [[ -e %s ]] && cp -r %s %s || true && %s",
				workdir,
				transFileReq.TargetFile,
				transFileReq.TargetFile,
				backup,
				fmt.Sprintf(
					`find . -maxdepth 1 -regextype posix-egrep -regex "./backup_[0-9]{14}_%s" -ctime +2 -exec rm -r {} \;`,
					transFileReq.TargetFile,
				),
			))
		}

		// 对目标机上文件进行替换
		if code := transFileReq.Code; code != "" {
			switch code {
			case "zip":
				commands = append(commands, fmt.Sprintf(
					"cd %s && unzip -o %s",
					workdir,
					sourceFileTmp,
				))
			case "gzip":
				commands = append(commands, fmt.Sprintf(
					"cd %s && gunzip -f -d %s",
					workdir,
					sourceFileTmp,
				))
			case "tgz", "tar.gz":
				commands = append(commands, fmt.Sprintf(
					"cd %s && tar zxvf %s",
					workdir,
					sourceFileTmp,
				))
			default:
				detail := fmt.Sprintf("code param not support: %s", code)
				clog.Error("%s code param err, req: %v", fun, code)
				online.ReplyFailWithDetail(w, lib.CodePara, detail)
				return
			}
		} else {
			commands = append(commands, fmt.Sprintf(
				"cd %s && mv %s %s",
				workdir,
				sourceFileTmp,
				transFileReq.TargetFile,
			))
		}

		if output, err := SSHCommand(client, commands); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, commands, output)
			online.ReplyFailWithDetail(w, lib.CodeSrv, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, commands, output)
		}
	}

	resp := &TransFileRsp{}
	online.ReplyOk(w, resp)

	return
}
