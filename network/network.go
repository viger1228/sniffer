package network

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
	"github.com/viger1228/sniffer/process"
)

var PROC_PATH = map[string]string{
	"tcp":  "/proc/net/tcp",
	"udp":  "/proc/net/udp",
	"tcp6": "/proc/net/tcp6",
	"udp6": "/proc/net/udp6",
}

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type ConnState struct {
	Pid         string
	Proc        string
	Cmd         string
	Uid         string
	User        string
	Type        string
	LocalIP     string
	LocalPort   int64
	ForeignIP   string
	ForeignPort int64
	Socket      string
	State       string
	PPid        []string
}

var ConnStates map[string]ConnState

var NetworkChan = make(chan interface{}, 10240)

func init() {
	process.Stats()
}

func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return d
}

func parseAddr(s string) (string, int64) {
	array := strings.Split(s, ":")
	hexIP := array[0]
	hexIP = hexIP[len(hexIP)-8 : len(hexIP)]
	hexPort := array[1]
	decIP := fmt.Sprintf("%d.%d.%d.%d",
		hexToDec(hexIP[6:8]),
		hexToDec(hexIP[4:6]),
		hexToDec(hexIP[2:4]),
		hexToDec(hexIP[0:2]),
	)
	decPort := hexToDec(hexPort)
	return decIP, decPort
}

func getUser(s string) string {
	u, _ := user.LookupId(s)
	return u.Username
}

// 讀取 "/proc/net/{tcp|upd}"
func getNet(t string, procPath string) {

	data, err := ioutil.ReadFile(procPath)

	if err != nil {
		log.Println(err)
		log.Println(procPath)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines[1 : len(lines)-1] {
		conn := parseNet(l, t)
		key := fmt.Sprintf("%v-%v-%v-%v",
			conn.LocalIP, conn.LocalPort,
			conn.ForeignIP, conn.ForeignPort)
		ConnStates[key] = conn
	}
}

// 解析 "/proc/net/{tcp|upd}"
func parseNet(s string, t string) ConnState {
	var conn ConnState
	var array []string

	for _, v := range strings.Split(strings.TrimSpace(s), " ") {
		if v != "" {
			array = append(array, v)
		}
	}

	conn.LocalIP, conn.LocalPort = parseAddr(array[1])
	conn.ForeignIP, conn.ForeignPort = parseAddr(array[2])
	conn.State = STATE[array[3]]
	conn.Type = t
	conn.Uid = array[7]
	conn.User = getUser(array[7])
	socket := array[9]
	conn.Socket = socket
	if _, ok := process.Socket2Proc[socket]; !ok && socket != "0" {
		//fmt.Printf("%s not found, refresh ths process\n", socket)
		process.Stats()
	}
	pid := process.Socket2Proc[socket]
	conn.Pid = pid
	conn.Proc = process.Proc[pid].Name
	conn.Cmd = process.Proc[pid].Cmd
	ppid := process.Proc[pid].PPid
	for {
		conn.PPid = append([]string{ppid}, conn.PPid...)
		if ppid != "1" && ppid != "" {
			ppid = process.Proc[ppid].PPid
		} else {
			break
		}
	}
	return conn
}

func Stats() {

	for k, v :=range PROC_PATH{
		_, err := os.Stat(v)
		if os.IsNotExist(err){
			PROC_PATH[k] = ""
		}
	}

	for {
		ConnStates = map[string]ConnState{}
		for k, v :=range PROC_PATH{
			if v == "" {
				continue
			}
			getNet(k, v)
		}
		NetworkChan <- ConnStates
		time.Sleep(time.Millisecond * 100)
	}
}
