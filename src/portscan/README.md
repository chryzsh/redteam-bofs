# portscan

TCP connect scan of one host or a file of hosts.

## Overview

`portscan` opens non-blocking TCP connections and waits for them with `select()`. Up to 128 connections are in flight at once. A port is:

- **open** if the handshake completes
- **closed** if the target answers with RST
- **filtered** if nothing comes back before the timeout (default 1000 ms)

Each connection is closed with RST (`SO_LINGER` 0), so no sockets stay in TIME_WAIT on the beacon host.

This is a connect scan, not a SYN scan. Windows does not allow raw TCP sockets, so open ports see a full handshake and can show up in target connection logs.

Probes go port by port across all hosts, which spreads the load instead of sending many ports to one host at once.

## Usage

### Single Host

```
portscan DC01 445,3389
portscan 10.0.0.5 1-1024 500
```

### Multiple Hosts (file upload)

OC2: upload a hosts file through the GUI, then run:
```
portscan-file 445
portscan-file 80,443 500
```

Cobalt Strike: pass the file path on the operator's system:
```
portscan /tmp/resolved.txt 445
```

### Hosts File Format

One host per line. Each line can be:

- a hostname: `ws01.example.local`
- an IP: `10.0.0.21`
- `nslookup-file` output: `ws01.example.local<TAB>10.0.0.21[,ip...]`

When a line has an IP, the BOF uses the first IP and does not resolve the hostname again. Otherwise it resolves the hostname with `getaddrinfo`, one host at a time.

### Ports

Comma-separated, ranges allowed: `445`, `80,443`, `1-1024,3389,8000-8100`.

### Output

One line per open port, as `host:port`:
```
[*] Scanning 3 hosts on 2 ports, 1000 ms timeout
ws01.example.local:445
fileserver.example.local:445
fileserver.example.local:3389
[+] Done. 3 open, 2 closed, 1 filtered, 0 failed, 0 hosts not resolved
```

## Build

```bash
make          # Build x64 + x86
make clean    # Remove artifacts
```
