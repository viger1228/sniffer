package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"time"
)

var IF_IP = ""

type TCPInfo struct {
	Id       string
	Time     string
	Timestamp int64
	Pid      string
	PPid     []string
	Flag     []string
	User     string
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Name     string
	Cmd      string
	Socket   string
}

type DNSInfo struct {
	Id      string
	Time    string
	Timestamp int64
	Pid     string
	PPid    []string
	User    string
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Name    string
	Cmd     string
	Socket  string
	Query   string
	Type    string
	Record  string
	Records []string
}

var PacketChan = make(chan interface{}, 10240)

func getDev() string {
	devName := ""
	devs, _ := pcap.FindAllDevs()
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.String() == IF_IP {
				devName = dev.Name
			}
		}
	}
	if devName == "" {
		fmt.Printf("%s doesn't exist!\n", IF_IP)
		return ""
	}
	return devName
}

func getIP(devName string) string {
	devs, _ := pcap.FindAllDevs()
	for _, dev := range devs {
		if dev.Name == devName {
			return dev.Addresses[0].IP.String()
		}
	}
	fmt.Printf("Can't find the IP from %s\n", devName)
	os.Exit(1)
	return ""
}

func getPacket(d string) {
	snapLen := int32(65535)

	// 抓包
	handle, err := pcap.OpenLive(d, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		return
	}
	defer handle.Close()

	// 解析包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	//port := 53
	for packet := range packetSource.Packets() {
		// 解析
		eth := layers.Ethernet{}
		ip := layers.IPv4{}
		tcp := layers.TCP{}
		udp := layers.UDP{}
		dns := layers.DNS{}
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &ip, &tcp, &udp, &dns,
		)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &decoded)

		if ip.Contents == nil || (ip.SrcIP.String() != IF_IP && ip.DstIP.String() != IF_IP) {
			continue
		}

		if tcp.Contents != nil && (tcp.SYN || tcp.FIN || tcp.RST) {
			flag := map[string]bool{
				"FIN": tcp.FIN,
				"SYN": tcp.SYN,
				"RST": tcp.RST,
				"PSH": tcp.PSH,
				"ACK": tcp.ACK,
				"URG": tcp.URG,
				"ECE": tcp.ECE,
				"CWR": tcp.CWR,
				"NS":  tcp.NS,
			}
			now := time.Now()
			tcpInfo := TCPInfo{
				Time:     now.Format("2006/1/2 15:04:05"),
				Timestamp: now.UnixNano(),
				SrcIP:    fmt.Sprintf("%v", ip.SrcIP),
				SrcPort:  uint16(tcp.SrcPort),
				DstIP:    fmt.Sprintf("%v", ip.DstIP),
				DstPort:  uint16(tcp.DstPort),
			}
			for k, v := range flag {
				if v {
					tcpInfo.Flag = append(tcpInfo.Flag, k)
				}
			}
			PacketChan <- tcpInfo
		}

		if dns.Contents != nil {
			now := time.Now()
			dnsInfo := DNSInfo{
				Time:     now.Format("2006/1/2 15:04:05"),
				Timestamp: now.UnixNano(),
				SrcIP: fmt.Sprintf("%v", ip.SrcIP),
				DstIP: fmt.Sprintf("%v", ip.DstIP),
			}
			if udp.Contents != nil {
				dnsInfo.SrcPort = uint16(udp.SrcPort)
				dnsInfo.DstPort = uint16(udp.DstPort)
			} else if tcp.Contents != nil {
				dnsInfo.SrcPort = uint16(tcp.SrcPort)
				dnsInfo.DstPort = uint16(tcp.DstPort)
			} else {
				continue
			}

			dnsInfo.Query = string(dns.Questions[0].Name)
			dnsInfo.Type = dns.Questions[0].Type.String()
			for _, v := range dns.Answers {
				dnsInfo.Records = append(dnsInfo.Records, string(v.Name))
				if v.IP != nil {
					dnsInfo.Records = append(dnsInfo.Records, v.IP.String())
					dnsInfo.Record = v.IP.String()
				}
			}
			PacketChan <- dnsInfo
		}
	}

}

func Stats(devName string) {
	IF_IP = getIP(devName)
	getPacket(devName)
}
