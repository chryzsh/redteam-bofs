# nslookup-file

Resolve a file of hostnames to IPv4 addresses with parallel DNS queries.

## Overview

`nslookup-file` reads a newline-separated list of hostnames and resolves each one with `DnsQueryEx` in asynchronous mode. Up to 64 queries run at the same time. A query that has no answer after 5 seconds is cancelled and counted as timed out.

LLMNR and NetBIOS fallback are disabled (`DNS_QUERY_NO_MULTICAST | DNS_QUERY_NO_NETBT`). A name that is not in DNS fails fast and does not send broadcast traffic.

Requires Windows 8 / Server 2012 or later (`DnsQueryEx`).

For a single lookup, use `nslookup` from [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF).

## Usage

### OC2

Upload a hostnames file through the GUI, then run:
```
nslookup-file
nslookup-file 10.0.0.10      # query a specific DNS server
```

### Cobalt Strike

Pass the file path on the operator's system:
```
nslookup-file /tmp/computers.txt
nslookup-file /tmp/computers.txt 10.0.0.10
```

### Hostnames File Format

One hostname per line. Only the first word of each line is used, so the output of this BOF can be fed back in.
```
dc01
ws01.example.local
fileserver.example.local
```

### Output

One line per host that resolves, as `hostname<TAB>ip[,ip...]`. Hosts that do not resolve are counted but not printed.
```
ws01.example.local	10.0.0.21
fileserver.example.local	10.0.0.30,10.0.1.30
[+] Done. 2 resolved, 1 not found, 0 timed out, 0 failed
```

The output can go straight into `portscan-file`, which uses the IP from each line and skips a second lookup.

## Build

```bash
make          # Build x64 + x86
make clean    # Remove artifacts
```
