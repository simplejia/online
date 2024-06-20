package online

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lib"

	clog "github.com/simplejia/clog/api"
	"golang.org/x/crypto/ssh"
)

// TransCmdWithJumpReq 接受值
type TransCmdWithJumpReq struct {
	JumpHost    string   `json:"jump_host"` // maybe empty
	JumpDir     string   `json:"jump_dir"`
	JumpPort    int      `json:"jump_port"`
	JumpUser    string   `json:"jump_user"`
	JumpPWD     string   `json:"jump_pwd"`
	TargetHosts []string `json:"target_hosts"`
	TargetPort  int      `json:"target_port"`
	TargetUser  string   `json:"target_user"`
	TargetPWD   string   `json:"target_pwd"`
	Cmd         string   `json:"cmd"`
}

// Regular 用于参数校验
func (transCmdWithJumpReq *TransCmdWithJumpReq) Regular() (ok bool) {
	if transCmdWithJumpReq == nil {
		return
	}

	if transCmdWithJumpReq.JumpHost == "" {
		return
	}

	if transCmdWithJumpReq.JumpDir == "" {
		transCmdWithJumpReq.JumpDir = "/tmp"
	}

	if transCmdWithJumpReq.JumpPort <= 0 {
		transCmdWithJumpReq.JumpPort = 22
	}

	if transCmdWithJumpReq.JumpUser == "" {
		return
	}

	if len(transCmdWithJumpReq.TargetHosts) <= 0 {
		return
	}

	if transCmdWithJumpReq.TargetPort <= 0 {
		transCmdWithJumpReq.TargetPort = 22
	}

	if transCmdWithJumpReq.TargetUser == "" {
		return
	}

	if transCmdWithJumpReq.Cmd == "" {
		return
	}

	ok = true
	return
}

// TransCmdWithJump
type TransCmdWithJumpRsp struct {
	Result map[string][]string `json:"result,omitempty"`
}

// TransCmdWithJump just for demo
// @prefilter("Auth")
// @postfilter("Boss")
func (online *Online) TransCmdWithJump(w http.ResponseWriter, r *http.Request) {
	fun := "online.Online.TransCmdWithJump"

	var transCmdWithJumpReq *TransCmdWithJumpReq
	if err := json.Unmarshal(online.ReadBody(r), &transCmdWithJumpReq); err != nil || !transCmdWithJumpReq.Regular() {
		clog.Error("%s param err: %v, req: %v", fun, err, transCmdWithJumpReq)
		online.ReplyFail(w, lib.CodePara)
		return
	}

	authMethod, err := GetAuthMethod(transCmdWithJumpReq.JumpPWD)
	if err != nil {
		clog.Error("%s GetAuthMethod err: %v, req: %v", fun, err, transCmdWithJumpReq.JumpPWD)
		online.ReplyFailWithDetail(w, lib.CodePara, err.Error())
		return
	}

	config := &ssh.ClientConfig{
		User: transCmdWithJumpReq.JumpUser,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * 5,
	}

	jumpHost := transCmdWithJumpReq.JumpHost

	client, err := ssh.Dial(
		"tcp",
		net.JoinHostPort(jumpHost, strconv.Itoa(transCmdWithJumpReq.TargetPort)),
		config,
	)
	if err != nil {
		clog.Error("%s ssh.Dial err: %v, req: %v", fun, err, jumpHost)
		online.ReplyFail(w, lib.CodeSrv)
		return
	}
	defer client.Close()

	workdir := transCmdWithJumpReq.JumpDir

	command := fmt.Sprintf(
		"cd %s && [[ ! -e %s ]] && echo -n '%s' > %s && chmod u+x %s || true",
		workdir,
		"exp_cmd.exp",
		ExpCmd,
		"exp_cmd.exp",
		"exp_cmd.exp",
	)

	if output, err := SSHCommand(client, []string{command}); err != nil {
		clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
		online.ReplyFailWithDetail(w, lib.CodeSrv, output)
		return
	} else {
		clog.Info("%s SSHCommand(exp) req: %v, resp: %v", fun, "", output)
	}

	result := map[string][]string{}

	for _, targetHost := range transCmdWithJumpReq.TargetHosts {
		clog.Info("%s target: %s", fun, targetHost)

		command := fmt.Sprintf(
			`%s %s %s "%s" "%s"`,
			filepath.Join(transCmdWithJumpReq.JumpDir, "exp_cmd.exp"),
			transCmdWithJumpReq.TargetUser,
			targetHost,
			transCmdWithJumpReq.TargetPWD,
			transCmdWithJumpReq.Cmd,
		)

		if output, err := SSHCommand(client, []string{command}); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
			online.ReplyFailWithDetail(w, lib.CodePara, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
			result[targetHost] = strings.Split(output, "\n")
		}
	}

	resp := &TransCmdWithJumpRsp{
		Result: result,
	}
	online.ReplyOk(w, resp)

}
