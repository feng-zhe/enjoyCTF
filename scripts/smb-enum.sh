#!/bin/bash
ip=$1
echo "try smbclient"
echo xxx | smbclient -L $ip

echo "try smbmap"
smbmap -H $ip -R --depth 5
smbmap -H $ip -R --depth 5 -u root -p xxx

echo "try nbtscan"
nbtscan -r $ip

echo "try enum4linux"
enum4linux -a $ip
