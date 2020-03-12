# SMBCompScan
Scanner script to identify hosts vulnerable to CVE-2020-0796

[Advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796)

## Disclaimer
This script can help to identify machines with the SMBv3 vulnerablity by checking for enabled compression. Still, it might return "vulnerable" for machines which have KB4551762 installed.

## Requirements
* Perl 5.12+
* IO::Socket
* Net::Netmask

## Usage
Scan a single IP address:
```sh
./smbCompScan.pl 192.168.0.1
```

Scan by hostname:
```sh
./smbCompScan.pl some.vulnerable.host.tld
```

Scan a network:
```sh
./smbCompScan.pl 192.168.0.0/24
```