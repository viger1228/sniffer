package main

import (
	"encoding/json"
	"github.com/viger1228/sniffer/network"
	"github.com/viger1228/sniffer/packet"
	"github.com/viger1228/sniffer/output"
	"log"

	"fmt"
	"github.com/go-yaml/yaml"
	"io/ioutil"
	"os"
)

var DataChan = make(chan interface{}, 10240)

var TCPPacket []packet.TCPInfo

var DNSPacket []packet.DNSInfo

var confData map[string]interface{}
var confPath string

func init(){
	log.SetFlags(log.Ldate|log.Ltime|log.Lshortfile)
	confData = confFile()

	jsonData, _ := json.MarshalIndent(confData, "", " ")
	fmt.Println("Security Sniffer Starting...")
	fmt.Printf("Configure from %s\n", confPath)
	fmt.Println(string(jsonData))
}

func main(){

	snifferTCP := confData["sniffer-tcp"].(bool)
	snifferDNS := confData["sniffer-dns"].(bool)
	//snifferCMD := confData["sniffer-cmd"].(bool)

	devName := confData["interface"].(string)

	if snifferTCP || snifferDNS {
		go network.Stats()
		go packet.Stats(devName)
	}

	go func(){
		for c := range network.NetworkChan{
			DataChan <- c
		}
	}()
	go func(){
		for c := range packet.PacketChan{
			DataChan <- c
		}
	}()

	output.ConfFile = confData
	allocate()
}

func confFile()map[string]interface{}{
	yamlData := map[string]interface{}{
		"sniffer-tcp": true,
		"sniffer-dns": true,
		"sniffer-cmd": true,
		"interface": "eth0",
		"console": true,
		"logfile": true,
		"logpath": "/var/log/sniffer",
		"elastic": false,
		"elastichost": "http://elastic:9200",
	}

	confPath = "/etc/sniffer/sniffer.yml"
	_, err := os.Lstat("sniffer.yml")
	if !os.IsNotExist(err){
		confPath = "sniffer.yml"
	}
	file, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	err = yaml.Unmarshal(file, &yamlData)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	return yamlData
}

func allocate(){
	for data := range DataChan{
		switch d := data.(type) {
		case packet.TCPInfo:
			key := ""
			if d.SrcIP == packet.IF_IP {
				key = fmt.Sprintf("%v-%v-%v-%v",
					d.SrcIP, d.SrcPort, d.DstIP, d.DstPort)
			} else if d.DstIP == packet.IF_IP {
				key = fmt.Sprintf("%v-%v-%v-%v",
					d.DstIP, d.DstPort, d.SrcIP, d.SrcPort)
			}
			d.Id = key
			TCPPacket = append(TCPPacket, d)
		case packet.DNSInfo:
			key := ""
			if d.SrcIP == packet.IF_IP {
				key = fmt.Sprintf("%v-%v-%v-%v",
					d.SrcIP, d.SrcPort, d.DstIP, d.DstPort)
			} else if d.DstIP == packet.IF_IP {
				key = fmt.Sprintf("%v-%v-%v-%v",
					d.DstIP, d.DstPort, d.SrcIP, d.SrcPort)
			}
			d.Id = key
			DNSPacket = append(DNSPacket, d)
		case map[string]network.ConnState:
			for _, p := range TCPPacket{
				conn := d[p.Id]
				p.Name = conn.Proc
				p.User = conn.User
				p.Pid = conn.Pid
				p.Cmd = conn.Cmd
				p.PPid = conn.PPid
				p.Socket = conn.Socket
				output.Output("sniffer-tcp", p)
			}
			TCPPacket = []packet.TCPInfo{}
			for _, p := range DNSPacket{
				conn := d[p.Id]
				p.Name = conn.Proc
				p.User = conn.User
				p.Pid = conn.Pid
				p.Cmd = conn.Cmd
				p.PPid = conn.PPid
				p.Socket = conn.Socket
				output.Output("sniffer-dns", p)
			}
			DNSPacket = []packet.DNSInfo{}
		}
	}
}
