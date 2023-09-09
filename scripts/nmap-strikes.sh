#!/bin/bash
ip=$1
mkdir nmap 2>/dev/null
nmap -Pn -sV -sC $ip > nmap/comm-tcp.nmap &
nmap -Pn -sV -p- $ip > nmap/all-tcp.nmap &
nmap -Pn -sV -sU $ip > nmap/comm-udp.nmap &
#nmap -Pn -sV -sU -p- $ip > nmap/all-udp &
nmap -Pn --script=vuln $ip > nmap/vuln.nmap &
