# SMBCompScan
Scanner script to identify hosts vulnerable to CVE-2020-0796

## Requirements
* Perl 5.12+
* IO::Socket
* Net::Netmask

## Usage
Scan a single IP address:
```sh
./smbCompScan.pl 192.168.0.1
```

Scan a network:
```sh
./smbCompScan.pl 192.168.0.0/24
```
