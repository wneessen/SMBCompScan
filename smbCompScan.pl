#!/usr/bin/env perl
## Simple scanner script to identify hosts vulnerable to CVE-2020-0796
## Usage: ./smbCompScan.pl <ip address of host or network CIDR>
## Example: ./smbCompScan.pl 192.168.178.0/24
## (C) 2020 Winni Neessen <wn@neessen.net>

use strict;
use warnings;
use v5.12;
use IO::Socket;
use Net::Netmask;

use constant SMBPORT => 445;
use constant PAYLOAD => qq(\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02\$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00);

my $targetIp = $ARGV[0];
if(!defined($targetIp)) {
    say "Usage: $0 <target ip or cidr>";
    exit 1;
}

foreach my $checkIp (Net::Netmask->new($targetIp)->enumerate) {
    print 'Checking ' . $checkIp . ' => ';
    my $smbClient = eval {
        IO::Socket->new(
            Domain      => AF_INET,
            Type        => SOCK_STREAM,
            proto       => 'tcp',
            PeerHost    => $checkIp,
            PeerPort    => SMBPORT,
            Timeout     => 2,
        ) or die $!;
    };
    if($@) {
        say 'unreachable';
        next;
    }
    
    $smbClient->send(PAYLOAD);
    $smbClient->shutdown(SHUT_WR);
    my $smbRetSize;
    $smbClient->recv($smbRetSize, 4);
    my $readSize = unpack('I*', $smbRetSize);
    my $smbReturn;
    $smbClient->recv($smbReturn, $readSize);
    my @byteArray = unpack('U*', $smbReturn);
    if(($byteArray[68] == 17 && $byteArray[70] == 2) || ($byteArray[70] == 2 && $byteArray[72] == 85)) {
        say 'vulnerable';
    }
    else {
        say 'not vulnerable';
    }
    $smbClient->close();
}