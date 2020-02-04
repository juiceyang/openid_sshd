package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/gliderlabs/ssh"
	"github.com/kr/pty"
	gossh "golang.org/x/crypto/ssh"
)

var (
	openIDCh = make(chan IntrospectResp)
)

func handleSession(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		io.WriteString(s, "Invalid request.\n")
		s.Exit(1)
	}
	cmd := exec.Command("bash")
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	f, err := pty.Start(cmd)
	if err != nil {
		panic(err)
	}
	go func() {
		for win := range winCh {
			func(file *os.File, w int, h int) {
				syscall.Syscall(
					syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCSWINSZ),
					uintptr(
						unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0}),
					),
				)
			}(f, win.Width, win.Height)
		}
	}()
	go func() {
		io.Copy(f, s) // stdin
	}()
	io.Copy(s, f) // stdout
	cmd.Wait()
}

func serverOptions(srv *ssh.Server) error {
	srv.PasswordHandler = func(ctx ssh.Context, pwd string) bool {
		return false
	}
	srv.KeyboardInteractiveHandler = ssh.KeyboardInteractiveHandler(
		func(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
			u, state, err := generateAuthorizeUrl()
			if err != nil {
				panic(err)
			}
			instructions := "Please visit link below to take openID authentication."
			questions := []string{fmt.Sprintln(u.String(), "\nType y/Y after visiting the link:")}
			echos := []bool{true}

			timeoutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			challengerCh := make(chan []string)
			go func() {
				answers, err := challenger(ctx.User(), instructions, questions, echos)
				if err != nil {
					challengerCh <- nil
					return
				}
				challengerCh <- answers
			}()

			select {
			case answers := <-challengerCh:
				if answers == nil {
					return false
				}
				if strings.ToLower(answers[0]) != "y" {
					return false
				}
				for {
					select {
					case intro := <-openIDCh:
						if intro.State != state {
							openIDCh <- intro
							continue
						}
						fmt.Printf("User %v logged in.\n", intro.Username)
						return true
					case <-timeoutCtx.Done():
						fmt.Printf("User login timeout from %v\n", ctx.RemoteAddr().String())
						return false
					}
				}
			case <-timeoutCtx.Done():
				fmt.Printf("User login timeout from %v\n", ctx.RemoteAddr().String())
				return false
			}
		},
	)
	return nil
}

func sshListenAndServe() {
	addr := "127.0.0.1:2222"
	fmt.Printf("SSH server listening: %v\n", addr)
	ssh.ListenAndServe(
		addr,
		handleSession,
		serverOptions,
	)
}
