package online

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lib"

	"github.com/simplejia/clog"
	"golang.org/x/crypto/ssh"
)

// TransCmdReq 接受值
type TransCmdReq struct {
	TargetHosts []string `json:"target_hosts"`
	TargetPort  int      `json:"target_port"`
	TargetUser  string   `json:"target_user"`
	TargetPWD   string   `json:"target_pwd"`
	Cmd         string   `json:"cmd"`
}

// Regular 用于参数校验
func (transCmdReq *TransCmdReq) Regular() (ok bool) {
	if transCmdReq == nil {
		return
	}

	if len(transCmdReq.TargetHosts) <= 0 {
		return
	}

	if transCmdReq.TargetPort <= 0 {
		transCmdReq.TargetPort = 22
	}

	if transCmdReq.TargetUser == "" {
		return
	}

	if transCmdReq.Cmd == "" {
		return
	}

	ok = true
	return
}

// TransCmd
type TransCmdRsp struct {
	Result map[string][]string `json:"result,omitempty"`
}

// TransCmd just for demo
// @postfilter("Boss")
func (online *Online) TransCmd(w http.ResponseWriter, r *http.Request) {
	fun := "online.Online.TransCmd"

	var transCmdReq *TransCmdReq
	if err := json.Unmarshal(online.ReadBody(r), &transCmdReq); err != nil || !transCmdReq.Regular() {
		clog.Error("%s param err: %v, req: %v", fun, err, transCmdReq)
		online.ReplyFail(w, lib.CodePara)
		return
	}

	authMethod, err := GetAuthMethod(transCmdReq.TargetPWD)
	if err != nil {
		clog.Error("%s GetAuthMethod err: %v, req: %v", fun, err, transCmdReq.TargetPWD)
		online.ReplyFailWithDetail(w, lib.CodePara, err.Error())
		return
	}

	config := &ssh.ClientConfig{
		User: transCmdReq.TargetUser,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * 5,
	}

	result := map[string][]string{}

	for _, targetHost := range transCmdReq.TargetHosts {
		clog.Info("%s target: %s", fun, targetHost)

		client, err := ssh.Dial(
			"tcp",
			net.JoinHostPort(targetHost, strconv.Itoa(transCmdReq.TargetPort)),
			config,
		)
		if err != nil {
			clog.Error("%s ssh.Dial err: %v, req: %v", fun, err, targetHost)
			online.ReplyFail(w, lib.CodeSrv)
			return
		}
		defer client.Close()

		command := transCmdReq.Cmd
		if output, err := SSHCommand(client, []string{command}); err != nil {
			clog.Error("%s SSHCommand err: %v, req: %v, resp: %v", fun, err, command, output)
			online.ReplyFailWithDetail(w, lib.CodePara, output)
			return
		} else {
			clog.Info("%s SSHCommand req: %v, resp: %v", fun, command, output)
			result[targetHost] = strings.Split(output, "\n")
		}
	}

	resp := &TransCmdRsp{
		Result: result,
	}
	online.ReplyOk(w, resp)

}
