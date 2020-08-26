// +build windows
package sftpd

import (
	"encoding/binary"
	"fmt"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	winpty "github.com/iamacarpet/go-winpty"
	"golang.org/x/crypto/ssh"
	"io"
	"sync"
)

var (
	defaultShell = "cmd" // Shell used if the SHELL environment variable isn't set
	logShell     = "shellw"
)

func handleShell(req *ssh.Request, channel ssh.Channel, pty *winpty.WinPTY) bool{
	// Teardown session
	var once sync.Once
	close := func() {
		channel.Close()
		pty.Close()
		logger.Warn(logShell,"session closed")
	}

	// Pipe session to bash and visa-versa
	go func() {
		io.Copy(channel, pty.StdOut)
		once.Do(close)
	}()

	go func() {
		io.Copy(pty.StdIn, channel)
		once.Do(close)
	}()

	// We don't accept any commands (Payload),
	// only the default shell.
	if len(req.Payload) == 0 {
		//ok = true
	}
	return true
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}
func handlePtrReq(req *ssh.Request, wd string, perms []string) (*winpty.WinPTY){
	//pty, err := winpty.Open("", defaultShell)
	pty, err := winpty.OpenWithOptions(winpty.Options{
		DLLPrefix: "",
		Command:   defaultShell,
		Dir: wd,
	})
	if err != nil {
		logger.Error("Failed to start command: %s\n", err.Error())
	}
	//Set the size of the pty
	termLen := req.Payload[3]
	termEnv := string(req.Payload[4 : termLen+4])
	w, h := parseDims(req.Payload[termLen+4:])
	//SetWinsize(fPty.Fd(), w, h)
	logger.Debug(logShell, "pty-req '%s'", termEnv)
	//pty.SetSize(200, 60)
	pty.SetSize(w, h)
	for _, v := range perms {
		if len(v) > 5 && v[:5] == "EXEC " {
			pty.StdIn.WriteString(v[5:])
			pty.StdIn.WriteString("\r\n")
			fmt.Printf("pre exec %s\n", v)
		}
	}

	return pty
}
func handleWindowChanged(req *ssh.Request, pty *winpty.WinPTY) {
	w, h := parseDims(req.Payload)
	pty.SetSize(w, h)
}


func handleSSHRequest(in <-chan *ssh.Request, channel ssh.Channel, connection Connection, c Configuration) {
	var pty *winpty.WinPTY = nil
	for req := range in {
		ok := false
		logger.Debug(logSender,"--- req.Type: [%s] payload [%s]\n", req.Type, string(req.Payload))

		switch req.Type {
		case "subsystem":
			if string(req.Payload[4:]) == "sftp" {
				ok = true
				connection.protocol = protocolSFTP
				go c.handleSftpConnection(channel, connection)
			}
		case "exec":
			if c.IsSCPEnabled {
				var msg execMsg
				if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
					name, scpArgs, err := parseCommandPayload(msg.Command)
					logger.Debug(logSender, "new exec command: %v args: %v user: %v, error: %v", name, scpArgs,
						connection.User.Username, err)
					if err == nil && name == "scp" && len(scpArgs) >= 2 {
						ok = true
						connection.protocol = protocolSCP
						scpCommand := scpCommand{
							connection: connection,
							args:       scpArgs,
							channel:    channel,
						}
						go scpCommand.handle()
					}
				}
			}
		case "pty-req":
			if connection.User.HasPerm(dataprovider.PermShell) {
				// Responding 'ok' here will let the client
				// know we have a pty ready for input
				ok = true
				pty = handlePtrReq(req, connection.User.HomeDir, connection.User.Permissions)
				if pty == nil {
					ok = false
				}
			}else{
				ok = false
				logger.Warn(logShell, "Denied shell of user [%s]\n", connection.User.Username)
			}
		case "shell":
			if pty == nil {
				logger.Warn(logShell, "pty not open yet!")
				ok = false
			} else {
				ok = handleShell(req, channel, pty)
			}
		case "window-change":
			if pty == nil {
				logger.Warn(logShell, "pty not open yet!")
				ok = false
			}else {
				handleWindowChanged(req, pty)
			}
			continue //no response
		case "env":

		}
		req.Reply(ok, nil)
	}
	logger.Debug(logSender, " --request process exited...")
}
