# Security Sniffer

[![](https://img.shields.io/badge/powered%20by-walker-brightgreen.svg?style=flat-square)](https://github.com/viger1228) 

[English](https://github.com/viger1228/sniffer/blob/master/README.md) | [繁體中文](https://github.com/viger1228/sniffer/blob/master/README.zh-tw.md)

No matter what method is used by the Hacker to hack the server, it would left access records behind on network layer. Security Sniffer can sniffer the TCP and DNS package currently, record in local file  or send to the ELK service.

## Install：

```shell
yum install -y https://github.com/viger1228/sniffer/releases/download/0.1/sniffer-0.1.0.x86_64.rpm
```

## Settings：

```yaml
vim /etc/sniffer/sniffer.yml

# Target
# Support TCP and DNS, but CMD sniffer is unfinished.
sniffer-tcp: True
sniffer-dns: True
sniffer-cmd: False

# Monitor Interface
interface: 'eth0'

# Exclude IP or Port
# excludeIP: ['127.0.0.1']
# excludePort: [22,23]
excludeIP: []
excludePort: [9200]

# Ouput to console，can use command 'journalctl -u sniffer' to show
console: True

# Ouput to local file
logfile: True
logpath: '/var/log/sniffer'

# Output to ELK server
elastic: True
elastichost: 'http://elastic:9200'
```

## Startup & Auto Startup

```shell
systemctl start sniffer
systemctl enable sniffer
```

## License

 [MIT](https://github.com/viger1228/nginx-waf/blob/master/LICENSE) © Walker

