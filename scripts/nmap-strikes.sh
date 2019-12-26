#!/bin/bash
ip=$1
mkdir nmap 2>/dev/null
nmap -sC -sV -oA nmap/comm-tcp $ip &
nmap -p- -sV $ip | tee nmap/all-tcp &
nmap -sU $ip | tee nmap/comm-udp &
nmap -p- -sU $ip | tee nmap/all-udp &
