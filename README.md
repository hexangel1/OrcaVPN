# OrcaVPN
VPN client server encrypted tunnel over UDP for Linux

* XChaCha20 Poly1305 & AES-CBC HMAC-SHA1 ciphers
* UDP transport layer protocol
* Multiple clients server-side support
* Server protection by blocking IP
* Bypass DPI using junk packets
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
* Override env variables in `/usr/local/etc/orcavpn.env`
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
    # OrcaVPN server config
    [server]
    # listen ip, default 0.0.0.0
    ip = 0.0.0.0
    # listen port, default 778
    port = 778

    # tun interface name
    tun_name = orca-gate
    # tun interface address
    tun_addr = 10.80.80.1
    # tun interface netmask
    tun_mask = 255.255.255.0
    # tun interface persist mode
    tun_persist = off

    # block enemy ip for ttl seconds, default disabled
    block_ip_ttl = 60

    # client sections
    [clientX]
    # private ip
    ip = 10.80.80.2
    # encryption key
    key = 9f840f9cedc92e3968ef6c86cfc62f3400b1334a60e27799573d733b1038b28d
    # encryption algorithm: xchacha20-poly1305|aes-hmac-sha1
    cipher = xchacha20-poly1305
    # enable internet access, default off
    inet = on
    # enable local network access, default off
    lan = on

    [clientY]
    ...


## Client config example
    # OrcaVPN client config
    [client]
    # server ip
    server_ip = 198.51.100.49
    # server port, default 778
    server_port = 778
    # local bind port, default any
    port = 0

    # tun interface name
    tun_name = orca-gate
    # tun interface address
    tun_addr = 10.80.80.2
    # tun interface netmask
    tun_mask = 255.255.255.0
    # tun interface persist mode
    tun_persist = off
    # server tun interface address
    router_ip = 10.80.80.1

    # junk packets count to send in [0, 1000]
    junk_count = 3
    # min junk packet size in [0, 128]
    junk_min = 64
    # max junk packet size in [junk_min, 1280]
    junk_max = 256

    # keepalive ping interval in seconds, default 10
    keepalive_intvl = 10
    # keepalive probes before connection is dead, default infinite
    keepalive_probes = 6

    # encryption key
    key = 9f840f9cedc92e3968ef6c86cfc62f3400b1334a60e27799573d733b1038b28d
    # encryption algorithm: xchacha20-poly1305|aes-hmac-sha1
    cipher = xchacha20-poly1305
