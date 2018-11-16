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

// TransFileWithJumpReq 接受值
type TransFileWithJumpReq struct {
	Code        string   `json:"code"`      // gzip, zip, tar, tgz, tar.gz
	JumpHost    string   `json:"jump_host"` // maybe empty
	JumpDir     string   `json:"jump_dir"`
	JumpPort    int      `json:"jump_port"`
	JumpUser    string   `json:"jump_user"`
	JumpPWD     string   `json:"jump_pwd"`
	TargetHosts []string `json:"target_hosts"`
	TargetDir   string   `json:"target_dir"`
	TargetFile  string   `json:"target_file"`
	TargetPort  int      `json:"target_port"`
	TargetUser  string   `json:"target_user"`
	TargetPWD   string   `json:"target_pwd"`
	Raw         string   `json:"raw"` // base64 encoding
}

// Regular 用于参数校验
func (transFileWithJumpReq *TransFileWithJumpReq) Regular() (ok bool) {
	if transFileWithJumpReq == nil {
		return
	}

	if transFileWithJumpReq.JumpHost == "" {
		return
	}

	if transFileWithJumpReq.JumpPort <= 0 {
		transFileWithJumpReq.JumpPort = 22
	}

	if transFileWithJumpReq.JumpUser == "" {
		return
	}

	if transFileWithJumpReq.JumpDir == "" {
		transFileWithJumpReq.JumpDir = "/tmp"
	}

	if len(transFileWithJumpReq.TargetHosts) <= 0 {
		return
	}

	if transFileWithJumpReq.TargetPort <= 0 {
		transFileWithJumpReq.TargetPort = 22
	}

	if transFileWithJumpReq.TargetUser == "" {
		return
	}

	if transFileWithJumpReq.TargetDir == "" {
		return
	}

	if transFileWithJumpReq.Raw == "" {
		return
	}

	code := strings.ToLower(transFileWithJumpReq.Code)
	switch code {
	case "", "gzip", "zip", "tar", "tgz", "tar.gz":
		transFileWithJumpReq.Code = code
	default:
		return
	}

	if code == "" && transFileWithJumpReq.TargetFile == "" {
		return
	}

	ok = true
	return
}

// TransFileWithJump
type TransFileWithJumpRsp struct {
}

// TransFileWithJump just for demo
func (online *Online) TransFileWithJump(w http.ResponseWriter, r *http.Request) {
	fun := "online.Online.TransFileWithJump"

	var transFileWithJumpReq *TransFileWithJumpReq
	if err := json.Unmarshal(online.ReadBody(r), &transFileWithJumpReq); err != nil || !transFileWithJumpReq.Regular() {
		clog.Error("%s param err: %v, req: %v", fun, err, transFileWithJumpReq)
		online.ReplyFail(w, lib.CodePara)
		return
	}

	data, err := base64.StdEncoding.DecodeString(transFileWithJumpReq.Raw)
	if err != nil {
		detail := "raw encoding unexpected"
		clog.Error("%s DecodeString err: %v, req: %v", fun, err, transFileWithJumpReq.Raw)
		online.ReplyFailWithDetail(w, lib.CodePara, detail)
		return
	}

	authMethod, err := GetAuthMethod(transFileWithJumpReq.JumpPWD)
	if err != nil {
		clog.Error("%s GetAuthMethod err: %v, req: %v", fun, err, transFileWithJumpReq.JumpPWD)
		online.ReplyFailWithDetail(w, lib.CodePara, err.Error())
		return
	}

	config := &ssh.ClientConfig{
		User: transFileWithJumpReq.JumpUser,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * 5,
	}

	jumpHost := transFileWithJumpReq.JumpHost

	client, err := ssh.Dial(
		"tcp",
		net.JoinHostPort(jumpHost, strconv.Itoa(transFileWithJumpReq.TargetPort)),
		config,
	)
	if err != nil {
		clog.Error("%s ssh.Dial err: %v, req: %v", fun, err, jumpHost)
		online.ReplyFail(w, lib.CodeSrv)
		return
	}
	defer client.Close()

	workdir := transFileWithJumpReq.JumpDir

	commands := []string{}

	commands = append(commands, fmt.Sprintf(
		"cd %s && [[ ! -e %s ]] && echo -n '%s' > %s && chmod u+x %s || true",
		workdir,
		"exp_cmd.exp",
		ExpCmd,
		"exp_cmd.exp",
		"exp_cmd.exp",
	))

	commands = append(commands, fmt.Sprintf(
		"cd %s && [[ ! -e %s ]] && echo -n '%s' > %s && chmod u+x %s || true",
		workdir,
		"exp_scp.exp",
		ExpScp,
		"exp_scp.exp",
		"exp_scp.exp",
	))

	if output, err := SSHCommand(client, commands); err != nil {
		clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, commands, output)
		online.ReplyFailWithDetail(w, lib.CodeSrv, output)
		return
	} else {
		clog.Info("%s SSHCommand(exp) req: %v, resp: %v", fun, "", output)
	}

	//文件拷贝jump host
	sourceFileTmp := fmt.Sprintf(
		"tmp_%s",
		time.Now().Format("20060102150405"),
	)
	if transFileWithJumpReq.TargetFile != "" {
		sourceFileTmp = fmt.Sprintf(
			"%s_%s",
			sourceFileTmp,
			transFileWithJumpReq.TargetFile,
		)
	}
	jfile := filepath.Join(workdir, sourceFileTmp)
	if output, err := SSHScp(client, data, jfile); err != nil {
		clog.Error("%s SSHScp err: %v, req: %v, resp: %v", fun, err, jfile, output)
		online.ReplyFailWithDetail(w, lib.CodeSrv, output)
		return
	} else {
		clog.Info("%s SSHScp req: %v, resp: %v", fun, "", output)
	}

	defer func() {
		command := fmt.Sprintf(
			"[[ -e %s ]] && rm %s || true",
			jfile,
			jfile,
		)

		if output, err := SSHCommand(client, []string{command}); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
		}
	}()

	//对多个目标机进行操作
	for _, targetHost := range transFileWithJumpReq.TargetHosts {
		clog.Info("%s target: %s", fun, targetHost)

		var backup string
		var command string
		var commands []string

		workdir := transFileWithJumpReq.TargetDir
		tfile := filepath.Join(workdir, sourceFileTmp)

		//文件拷贝目标主机
		command = fmt.Sprintf(
			"%s %s %s %s '%s' %s",
			filepath.Join(transFileWithJumpReq.JumpDir, "exp_scp.exp"),
			jfile,
			transFileWithJumpReq.TargetUser,
			targetHost,
			transFileWithJumpReq.TargetPWD,
			workdir,
		)

		if output, err := SSHCommand(client, []string{command}); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
			online.ReplyFailWithDetail(w, lib.CodeSrv, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
		}

		defer func() {
			command := fmt.Sprintf(
				"[[ -e %s ]] && rm %s || true",
				tfile,
				tfile,
			)

			command = fmt.Sprintf(
				"%s %s %s '%s' '%s'",
				filepath.Join(transFileWithJumpReq.JumpDir, "exp_cmd.exp"),
				transFileWithJumpReq.TargetUser,
				targetHost,
				transFileWithJumpReq.TargetPWD,
				command,
			)

			if output, err := SSHCommand(client, []string{command}); err != nil {
				clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
				return
			} else {
				clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
			}
		}()

		// 对目标机上文件首先进行备份，并删除过期文件(n天前)
		if transFileWithJumpReq.TargetFile != "" {
			backup = fmt.Sprintf(
				"backup_%s_%s",
				time.Now().Format("20060102150405"),
				transFileWithJumpReq.TargetFile,
			)
			commands = append(commands, fmt.Sprintf(
				"cd %s && [[ -e %s ]] && cp -r %s %s || true && %s",
				workdir,
				transFileWithJumpReq.TargetFile,
				transFileWithJumpReq.TargetFile,
				backup,
				fmt.Sprintf(
					`find . -maxdepth 1 -regextype posix-egrep -regex "./backup_[0-9]{14}_%s" -ctime +2 -exec rm -r {} \;`,
					transFileWithJumpReq.TargetFile,
				),
			))
		}

		// 对目标机上文件进行替换
		if code := transFileWithJumpReq.Code; code != "" {
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
				transFileWithJumpReq.TargetFile,
			))
		}

		command = fmt.Sprintf(
			`%s %s %s "%s" "%s"`,
			filepath.Join(transFileWithJumpReq.JumpDir, "exp_cmd.exp"),
			transFileWithJumpReq.TargetUser,
			targetHost,
			transFileWithJumpReq.TargetPWD,
			strings.Join(commands, " && "),
		)

		if output, err := SSHCommand(client, []string{command}); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
			online.ReplyFailWithDetail(w, lib.CodeSrv, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
		}
	}

	resp := &TransFileWithJumpRsp{}
	online.ReplyOk(w, resp)

	return
}
