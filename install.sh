#!/bin/bash
mkdir /usr/share/DNSInfo_IHA
mv APIkey /usr/share/DNSInfo_IHA
mv dnsinfo /usr/local/bin
chmod +x /usr/local/bin/dnsinfo
mv DNSInfo.py /usr/share/DNSInfo_IHA
echo "type 'dnsinfo' and use"
