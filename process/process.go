package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ProcState struct {
	Pid  string
	PPid string
	Name string
	Exe  string
	Cmd  string
	//Socket []string
}

var Socket2Proc map[string]string

var Proc map[string]ProcState

func getSocket(s string) string {
	reg := regexp.MustCompile("[0-9]+")
	r := reg.FindAllString(s, -1)
	return r[0]
}

func getPid(s string) string{
	seg := strings.Split(s, "/")
	return seg[2]
}

func setProc(p string){
	var proc ProcState
	path := fmt.Sprintf("/proc/%s/", p)
	proc.Pid = p
	proc.Exe, _ = os.Readlink(path + "exe")
	content, _ := ioutil.ReadFile(path + "cmdline")
	proc.Cmd = strings.Replace(string(content), "\u0000", "", -1)

	var array []string
	data, _ :=  ioutil.ReadFile(path + "stat")
	for _, d := range strings.Split(string(data), " "){
		if d != "" {
			array = append(array, d)
		}
	}
	if len(array) <= 4{
		return
	}
	name := array[1]
	ppid := array[3]
	proc.Name = name[1: len(name)-1]
	proc.PPid = ppid
	Proc[p] = proc
	if _, ok := Proc[ppid]; !ok && ppid != "1" && ppid != "0"{
		setProc(ppid)
	}
}

func Stats(){
	Socket2Proc = make(map[string]string)
	Proc = make(map[string]ProcState)
	var pids []string
	filePaths, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, path := range filePaths {
		link, _ := os.Readlink(path)
		if strings.Contains(link, "socket") {
			pid := getPid(path)
			socket := getSocket(link)
			Socket2Proc[socket] = pid
			pids = append(pids, pid)
		}
	}
	for _, p := range pids {
		if _, ok := Proc[p]; !ok {
			setProc(p)
		}
	}
}