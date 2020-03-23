# wgctl - WireGuard control utility

[![CI Status](https://img.shields.io/travis/apognu/wgctl/master.svg?style=flat-square)](https://travis-ci.org/apognu/wgctl)
[![Coverage Status](https://img.shields.io/coveralls/apognu/wgctl/master.svg?style=flat-square)](https://coveralls.io/github/apognu/wgctl?branch=master)

This is a personal project to allow WireGuard to be configured through the use of YAML files. It uses Netlink (through [wgctrl](https://golang.zx2c4.com/wireguard/wgctrl)) under the hood for all interaction with the system.

This tool is very opinionated and designed for my own use (working on that), it _might_ not be what you're looking for.

The configuration file (which is subject to breaking changes until 1.0) should look like this:

```yaml
description: Personal VPN server #1
private_key: /etc/wireguard/vpn1.key
peers:
  - description: Local laptop
    address: 192.168.0.1/32
    listen_port: 42000
    public_key: BooRta+d0t/2djkdZ3xfe/5xndKvPtfqH3pdZcdZ2TY=
    preshared_key: e16f1596201850fd4a63680b27f603cb64e67176159be3d8ed78a4403fdb1700
    fwmark: 1024
    routes: false
    post_up:
      - [ '/usr/bin/notify-send', 'WireGuard tunnel went up', 'A WireGuard tunnel was just brought up. Congrats.' ]
    pre_down:
      - [ '/usr/bin/notify-send', 'WireGuard tunnel went down', 'A WireGuard tunnel was just torn down. Congrats.' ]
  - description: VPN gateway at provider X
    address: 192.168.0.2/32
    listen_port: 42000
    public_key: cyfBMbaJ6kgnDYjio6xqWikvTz2HvpmvSQocRmF/ZD4=
    preshared_key: e16f1596201850fd4a63680b27f603cb64e67176159be3d8ed78a4403fdb1700
    endpoint: 1.2.3.4:42000
    keepalive_interval: 10s
    allowed_ips:
      - 192.168.0.0/30
      - 0.0.0.0/0
```

By default, ```wgctl``` will look for its configuration files under ```/etc/wireguard``` (as ```/etc/wireguard/<id>.yml```). This can be overriden by giving it a filesystem path instead of an identifier. You can alsow set the directory where ```wgctl``` looks for its configuration by settings the environment variable ```WGCTL_CONFIG_PATH```.

The ```post_up``` and ```pre_down``` directives take an array of arrays of commands to execute during the tunnel lifecycle events. You must use an absolute path to target the command you want to invoke.

Keep in mind that in order to put IPv6 addresses in the configuration, you'll need to coerce the value to a string with quotes :

```yaml
peers:
  - endpoint: '[cafe:1:2:3::1]:10000'
```

The configuration is built so as to be able to be copied on all peers identically, the current node is detected when a peer public key matches the private key at the root of the file.

## Build

```shell
$ go get -u github.com/apognu/wgctl
```

or

```shell
$ git clone https://github.com/apognu/wgctl.git && cd wgctl
$ dep ensure
$ go build .
```

You can, of course, get a prebuilt binary from the [Releases](https://github.com/apognu/wgctl/releases) section.

### Testing

You can run the tests for this project, as root (since we are testing netlink communication and device creation). Keep in mind that this will modify properties on your live system (devices, routes, /proc settings, etc.), so use with caution.

```shell
$ sudo -E go test ./... 
```

## Usage

```shell
$ wgctl help
usage: wgctl [<flags>] <command> [<args> ...]

WireGuard control plane helper

Flags:
  -h, --help  Show context-sensitive help (also try --help-long and --help-man).

Commands:
  help [<command>...]
  start [<flags>] <instance>
  stop <instance>
  restart [<flags>] <instance>
  status [<flags>] [<instance>]
  info <instance>
  set <instance> [<settings>...]
  peer
    set <instance> <peer>...
    replace <instance> <peer>...
  key
    private
    public
    psk
  version
```

### Control the state of tunnels

```shell
$ wgctl start -f vpn
$ wgctl start vpn
$ wgctl stop vpn
$ wgctl restart vpn
```

### Obtain the state of all configured or active tunnels

The ```-s``` option only displays the name of active tunnels, for ease of use in scripts.

```
$ wgctl status
[↓] tunnel 'vpn1' is down
[↑] tunnel 'vpn2' is up and running
[↓] tunnel 'corporate' is down
[↓] tunnel 'personal' is up and running

$ wgctl status -s
vpn2
personal

$ wgctl status vpn1
[↓] tunnel 'vpn1' is down
```

### Get configuration and runtime details for an active tunnel

```shell
$ wgctl info vpn2
tunnel: 
  interface: Personal VPN tunnel #2
  public key: SqtWXnIGoHWibfqZwAe6iFc560wWuV6zUL+4CqzDxlQ=
  port: 51822
  fwmark: 12548
  peer: VPN gateway
    public key: /7vJFkiTPPTznPvey4Z4+xn+HRGlT/X3hv1o4+kS7FQ=
    endpoint: 4.3.2.1:10000
    allowed ips: 192.168.0.1/30, 0.0.0.0/0
    transfer: ↓ 0 ↑ 0
```

### Change tunnel configuration on the fly

Those changes are not persisted, if you want to export the current configuration of a tunnel, use ```export``` below. Please note that you can provide a subset of the options shown below.

```shell
# Change properties on the interface itself
$ wgctl set vpn1 privkey=/etc/wireguard/new.key port=43210 fwmark=1437

# Add a new peer or change the properties of the peer with the given public key
$ wgctl peer set vpn1 pubkey=sSg9kL+KsMBQpFPO+TXl7A4OKjLb0xWORx7eR3JDjXM= endpoint=192.168.255.254:10000 allowedips=2.2.2.2/24,3.3.3.3/30 keepalive=20 psk=636493c476092bf06806794d6c2d62c990c68a39b71b73019a328a4d646d9e42

# Replace the whole set of peers with the given one
$ wgctl peer replace vpn1 pubkey=sSg9kL+KsMBQpFPO+TXl7A4OKjLb0xWORx7eR3JDjXM= endpoint=192.168.255.254:10000 allowedips=2.2.2.2/24,3.3.3.3/30 keepalive=20 psk=636493c476092bf06806794d6c2d62c990c68a39b71b73019a328a4d646d9e42
```

### Export the configuration of a tunnel

You can export the current configuration of an active tunnel by using the ```wgctl export``` command. If a ```wgctl``` configuration already exists, non-WireGuard properties (descriptions, hooks, etc.) will be merged with the running config. If not, the default values will be used.

Please note that if the tunnel was not created through ```wgctl```, the private key path will be left blank.

```shell
$ wgctl export vpn1
interface:
  description: Personal VPN server #1
  address: 192.168.0.1/32
  listen_port: 42000
  private_key: /path/to/private.key
  routes: false
  post_up:
    - [ '/usr/bin/notify-send', 'WireGuard tunnel went up', 'A WireGuard tunnel was just brought up. Congrats.' ]
  pre_down:
    - [ '/usr/bin/notify-send', 'WireGuard tunnel went down', 'A WireGuard tunnel was just torn down. Congrats.' ]
peers:
  - description: VPN gateway at provider X
    public_key: cyfBMbaJ6kgnDYjio6xqWikvTz2HvpmvSQocRmF/ZD4=
    preshared_key: e16f1596201850fd4a63680b27f603cb64e67176159be3d8ed78a4403fdb1700
    endpoint: 1.2.3.4:42000
    keepalive_interval: 10s
    allowed_ips:
      - 192.168.0.0/30
      - 0.0.0.0/0
```

### Generate keys to be used by WireGuard

```shell
$ wgctl key private
nAyxQotWfano6/cC9S6fjSRYe9oQ0/GQn2mK9/PXvyg=
$ wgctl key private | wgctl key public
OtvPEAa2d3PP0qAT9bm7zxdTLa6i6w2wNrCdziI76Hg=
$ wgctl key psk
d9c966f0cf2320d4e67d543e0a0cd3856fc0f065392799fff8e040bed51b3176
```

## Routes and firewall

By default, ```wgctl``` will add routes matching your allowed IP addresses in order to traffic to be routed through your VPN. Similarly to ```wg-quick```, il will set up any default routes to route all your traffic (with the ```fwmark``` technique).

If you want to manage the routing yourself, you can pass ```--no-routes``` to ```wgctl start``` and ```wgctl restart``` to prevent that behavior. You can also set the ```interface``` directive ```routes``` to ```false``` to disable this behavior permanently.

```wgctl``` will not touch your firewall rules, if you need to open a port or add specific rules, you'll need to do it yourself manually, or use a ```post_up``` directive.

## Use as a service

You can tell `wgctl` to stay in the foreground by starting your tunnel with the `-f` flag. This allows you to start up your tunnels as daemons with, for example, this `systemd` service unit:

```shell
$ cat /etc/systemd/system/wgctl@.service
[Unit]
Description=Wireguard tunnel

[Service]
Type=simple
Restart=always
WorkingDirectory=/etc/wireguard
ExecStart=/usr/local/bin/wgctl start -f %i
ExecStopPost=-/usr/local/bin/wgctl stop %i

[Install]
WantedBy=multi-user.target
```
