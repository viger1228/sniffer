# Security Sniffer

[![](https://img.shields.io/badge/powered%20by-walker-brightgreen.svg?style=flat-square)](https://github.com/viger1228) 

[English](https://github.com/viger1228/sniffer/blob/master/README.md) | [繁體中文](https://github.com/viger1228/sniffer/blob/master/README.zh-tw.md)

服務器無論是中木馬或是遭到入侵，黑客一定是會在網路層面留下痕跡。Security Sniffer 可以即時記錄TCP及DNS相關封包，並寫在本地日志或外傳到ELK。

## 安裝

```shell
yum install -y https://github.com/viger1228/sniffer/releases/download/0.1/sniffer-0.1.0.x86_64.rpm
```

## 配罝文件說明：

```yaml
vim /etc/sniffer/sniffer.yml

# Target
# 監控目標，支援TCP及DNS，CMD指令監控尚未完成
sniffer-tcp: True
sniffer-dns: True
sniffer-cmd: True

# 監聽網卡
interface: 'eth0'

# 忽略
# excludeIP: ['127.0.0.1']
# excludePort: [22,23]
excludeIP: []
excludePort: [9200]

# Ouput
# 輸出 Console，可用 journalctl -u sniffer 查看
console: True

# 輸出至文件
logfile: True
logpath: '/var/log/sniffer'

# 輸出至ELK
elastic: True
elastichost: 'http://elastic:9200'
```

## 啟動&開機啟動

```shell
systemctl start sniffer
systemctl enable sniffer
```

## License

 [MIT](https://github.com/viger1228/nginx-waf/blob/master/LICENSE) © Walker

