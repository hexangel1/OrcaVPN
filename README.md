# OrcaVPN
VPN client server AES encrypted tunnel over UDP for Linux

## Installation & Setup

* Download source code and get to repository root directory
* Run installation script with selected mode = `client` or `server`  
  `$ ./scripts/install.sh [mode]`
* Setup configuration in `/usr/local/etc/orcavpn.conf`
* Start orcavpn service  
  `$ systemctl start orcavpn.service`
* On client to route all traffic to the tunnel, run the command  
  `$ vpnclient-setup.sh [server_ip] [server_tun_ip] [default_router_ip]`

## Makefile commands

* `make orcavpn` - build project
* `make tar` - create tar archive with project files
* `make tags` - generate index file of names found in sources
* `make clean` - cleanup junk files

## Server config example
```
[server]  
ip = 192.168.1.1  
port = 778  
tun_name = orca-gate  
tun_addr = 10.80.80.1  
tun_netmask = 255.255.255.0  
[clientX]  
private_ip = 10.80.80.2  
point_id = 7  
cipher_key = dca1a0e8781bce8d51db8edf90c32bb3b45cac663adf2581  
inet = on  
lan = on  
[clientY]  
...
```

## Client config example
```
[client]  
ip = 0.0.0.0  
port = 778  
server_ip = 192.168.1.1  
server_port = 778  
tun_name = orca-gate  
tun_addr = 10.80.80.2  
tun_netmask = 255.255.255.0  
point_id = 7  
cipher_key = dca1a0e8781bce8d51db8edf90c32bb3b45cac663adf2581
```
