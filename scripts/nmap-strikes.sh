#!/bin/bash
ip=$1
mkdir nmap 2>/dev/null
nmap -sC -Pn -sV -oA nmap/comm-tcp $ip &>/dev/null &
nmap -p- -sV -Pn $ip > nmap/all-tcp &
nmap -sU -Pn $ip > nmap/comm-udp &
#nmap -p- -sU -Pn $ip > nmap/all-udp &
nmap --script=vuln -Pn $ip > nmap/vuln &
