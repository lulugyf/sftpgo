// +build !windows

package sftpd

import (
	"encoding/binary"
	"github.com/drakkan/sftpgo/logger"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

var (
	defaultShell = "sh" // Shell used if the SHELL environment variable isn't set
	logShell     = "shell"
)

// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	logger.Debug("", "window resize %dx%d", w, h)
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

func handleShell(req *ssh.Request, channel ssh.Channel, f, tty *os.File) bool{
	// allocate a terminal for this channel
	logger.Debug("shell", "creating pty...")

	var shell string
	shell = os.Getenv("SHELL")
	if shell == "" {
		shell = defaultShell
	}

	cmd := exec.Command(shell)
	cmd.Env = []string{"TERM=xterm"}
	err := PtyRun(cmd, tty)
	if err != nil {
		logger.Warn("", "%s", err)
	}

	// Teardown session
	var once sync.Once
	close := func() {
		channel.Close()
		logger.Warn(logShell,"session closed")
	}

	// Pipe session to bash and visa-versa
	go func() {
		io.Copy(channel, f)
		once.Do(close)
	}()

	go func() {
		io.Copy(f, channel)
		once.Do(close)
	}()

	// We don't accept any commands (Payload),
	// only the default shell.
	if len(req.Payload) == 0 {
		//ok = true
	}
	return true
}

func handlePtrReq(req *ssh.Request) (*os.File, *os.File){
	// Create new pty
	fPty, tty, err := pty.Open()
	if err != nil {
		logger.Warn(logShell, "could not start pty (%s)", err)
		return nil, nil
	}
	// Parse body...
	termLen := req.Payload[3]
	termEnv := string(req.Payload[4 : termLen+4])
	w, h := parseDims(req.Payload[termLen+4:])
	SetWinsize(fPty.Fd(), w, h)
	logger.Debug(logShell, "pty-req '%s'", termEnv)
	return fPty, tty
}

func handleWindowChanged(req *ssh.Request, fPty *os.File) {
	w, h := parseDims(req.Payload)
	SetWinsize(fPty.Fd(), w, h)
}




///////////////////////// Remote Port Forward  /////////////

type ForwardedTCPHandler struct {
	forwards map[string]net.Listener
	sync.Mutex
}

// ForwardedTCPHandler can be enabled by creating a ForwardedTCPHandler and
// adding the handlePortforward callback to the server's RequestHandlers under
// tcpip-forward and cancel-tcpip-forward.
func (h *ForwardedTCPHandler) handlePortforward(conn *ssh.ServerConn, req *ssh.Request) (bool, []byte, string) {
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]net.Listener)
	}
	h.Unlock()

	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
			logger.Error(logSender,"R Unmarshal failed %v", err)
			return false, []byte{}, ""
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		logger.Debug(logLforward, "bind addr: [%s]\n", addr)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			logger.Error(logSender,"R listen failed %v", err)
			return false, []byte{}, ""
		}
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)
		h.Lock()
		h.forwards[addr] = ln
		h.Unlock()
		go func() {
			logger.Debug(logSender,"   begin R accept...")
			for {
				c, err := ln.Accept()
				if err != nil {
					logger.Error(logSender,"R accept failed %v", err)
					break
				}
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := ssh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				go func() {
					ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
					if err != nil {
						logger.Error(logSender, "open forwarded-tcpip channel failed, %v", err)
						c.Close()
						return
					}
					go ssh.DiscardRequests(reqs)
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(ch, c)
					}()
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(c, ch)
					}()
				}()
			}
			h.Lock()
			delete(h.forwards, addr)
			h.Unlock()
		}()
		return true, ssh.Marshal(&remoteForwardSuccess{uint32(destPort)}), addr

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}, ""
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		h.Lock()
		ln, ok := h.forwards[addr]
		h.Unlock()
		if ok {
			ln.Close()
		}
		return true, nil, ""
	default:
		return false, nil, ""
	}
}





///////////////////////// Local Port Forward  /////////////
type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func HandleDirectTCPIP( conn *ssh.ServerConn, newChan ssh.NewChannel) {
	d := localForwardChannelData{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
	logger.Debug(logLforward, "forward to dest: %s", dest)

	var dialer net.Dialer
	dconn, err := dialer.Dial("tcp", dest)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
		logger.Debug(logLforward, "forward to [%s] done!!", dest)
	}()
}
