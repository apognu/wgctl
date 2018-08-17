# wgctl - WireGuard control utility

[![CI Status](https://img.shields.io/travis/apognu/wgctl/master.svg?style=flat-square)](https://travis-ci.org/apognu/wgctl)
[![Coverage Status](https://img.shields.io/coveralls/apognu/wgctl/master.svg?style=flat-square)](https://coveralls.io/github/apognu/wgctl?branch=master)

This is a personal project to allow WireGuard to be configured through the use of YAML files. It uses Netlink (through [wireguardctrl](https://github.com/mdlayher/wireguardctrl)) under the hood for all interaction with the system.

This tool is very opinionated and designed for my own use (working on that), it _might_ not be what you're looking for.

The configuration file (which is subject to breaking changes until 1.0) should look like this:

```
interface:
  description: Personal VPN server #1
  address: 192.168.0.1/32
  listen_port: 42000
  private_key: /etc/wireguard/vpn1.key
  fwmark: 1024
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

By default, ```wgctl``` will look for its configuration files under ```/etc/wireguard``` (as ```/etc/wireguard/<id>.yml```). This can be overriden by giving it a filesystem path instead of an identifier. You can alsow set the directory where ```wgctl``` looks for its configuration by settings the environment variable ```WGCTL_CONFIG_PATH```.

The ```post_up``` and ```pre_down``` directives take an array of arrays of commands to execute during the tunnel lifecycle events. You must use an absolute path to target the command you want to invoke.

Keep in mind that in order to put IPv6 addresses in the configuration, you'll need to coerce the value to a string with quotes :

```
peers:
  - endpoint: '[cafe:1:2:3::1]:10000'
```

## Build

```
$ go get -u github.com/apognu/wgctl
```

or

```
$ git clone https://github.com/apognu/wgctl.git && cd wgctl
$ dep ensure
$ go build .
```

### Testing

You can run the tests for this project, as root (since we are testing netlink communication and device creation). Keep in mind that this will modify properties on your live system, use with caution.

Test creation is under way, we have a lot left to do.

```
$ sudo -E go test ./... 
```

## Usage

```
# wgctl help
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
  key
    private
    public
    psk
  version

# wgctl start vpn
# wgctl stop vpn
# wgctl restart vpn

# wgctl status
[↓] tunnel 'vpn1' is down
[↑] tunnel 'vpn2' is up and running
[↓] tunnel 'corporate' is down
[↓] tunnel 'personal' is down

# wgctl info vpn2
tunnel: 
  interface: Perosnal VPN tunnel #2
  public key: SqtWXnIGoHWibfqZwAe6iFc560wWuV6zUL+4CqzDxlQ=
  port: 51822
  fwmark: 12548
  peer: VPN gateway
    public key: /7vJFkiTPPTznPvey4Z4+xn+HRGlT/X3hv1o4+kS7FQ=
    endpoint: 4.3.2.1:10000
    allowed ips: 192.168.0.1/30, 0.0.0.0/0
    transfer: ↓ 0 ↑ 0
```

## Routes and firewall

By default, ```wgctl``` will add routes matching your allowed IP addresses in order to traffic to be routed through your VPN. Similarly to ```wg-quick```, il will set up any default routes to route all your traffic (with the ```fwmark``` technique).

If you want to manage the routing yourself, you can pass ```--no-routes``` to ```wgctl start``` and ```wgctl restart``` to prevent that behavior. You can also set the ```interface``` directive ```routes``` to ```false``` to disable this behavior permanently.

```wgctl``` will not touch your firewall rules, if you need to open a port or add specific rules, you'll need to do it yourself manually, or use a ```post_up``` directive.
