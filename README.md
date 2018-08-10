# wgctl - WireGuard control utility

This is a personal project to allow WireGuard to be configured through the use of YAML files. It uses Netlink under the hood for all interaction with the system.

This tool is very opinionated and designed for my own use, it _might_ not be what you're looking for. For instance, it probably does not handle IPv6 very well for now.

The configuration file should look like this:

```
description: Personal VPN server #1
interface:
  address: 192.168.0.1/32
  listen_port: 42000
  private_key: /etc/wireguard/vpn1.key
  fwmark: 1024
peers:
  - description: VPN gateway at provider X
    public_key: cyfBMbaJ6kgnDYjio6xqWikvTz2HvpmvSQocRmF/ZD4=
    preshared_key: e16f1596201850fd4a63680b27f603cb64e67176159be3d8ed78a4403fdb1700
    endpoint: 1.2.3.4:42000
    keepalive_interval: 10
    allowed_ips:
      - 192.168.0.0/30
      - 0.0.0.0/0
```

By default, ```wgctl``` will look for its configuration files under ```/etc/wireguard``` (as ```/etc/wireguard/<id>.yml```). This can be overriden by giving it a filesystem path instead of an identifier. You can alsow set the directory where ```wgctl``` looks for its configuration by settings the environment variable ```WGCTL_CONFIG_PATH```.

Keep in mind that in order to put IPv6 addresses in the configuration, you'll need to coerce the value to a string with quotes :

```
peers:
  - endpoint: '[cafe:1:2:3::1]:10000'
```

## Build

```
$ go get -u github.com/apognu/wgctl
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
  interface: gcp
  public key: SqtWXnIGoHWibfqZwAe6iFc560wWuV6zUL+4CqzDxlQ=
  port: 51822
  fwmark: 12548
  peer: 
    public key: /7vJFkiTPPTznPvey4Z4+xn+HRGlT/X3hv1o4+kS7FQ=
    endpoint: 4.3.2.1:10000
    allowed ips: 192.168.0.1/30, 0.0.0.0/0
    transfer: ↓ 0 ↑ 0
```
