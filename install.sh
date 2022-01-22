#!/bin/bash
mkdir /usr/share/DNSInfo_IHA
touch /usr/share/DNSInfo_IHA/APIkey
cp dnsinfo /usr/local/bin
chmod +x /usr/local/bin/dnsinfo
cp DNSInfo.py /usr/share/DNSInfo_IHA
echo "type 'dnsinfo' and use"


