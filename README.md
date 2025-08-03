# OrcaVPN
VPN client server encrypted tunnel over UDP for Linux

* AES 128/192/256 bit CBC mode encryption
* SHA-1 packet signature
* UDP transport layer protocol
* Multiple clients server-side support
* Server protection by blocking IP
* Easy setup configuration
* Managed by systemd
* Builds with Make
* No dependencies on third-party libraries
* Works under Linux with TUN/TAP device driver

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
block_ip_ttl = 60  
[clientX]  
private_ip = 10.80.80.2  
cipher_key = dca1a0e8781bce8d51db8edf90c32bb3b45cac663adf2581  
inet = on  
lan = on  
[clientY]  
...
```

## Client config example
```
[client]  
server_ip = 192.168.1.1  
server_port = 778  
tun_name = orca-gate  
tun_addr = 10.80.80.2  
tun_netmask = 255.255.255.0  
cipher_key = dca1a0e8781bce8d51db8edf90c32bb3b45cac663adf2581
```
