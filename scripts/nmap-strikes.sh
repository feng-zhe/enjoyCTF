#!/bin/bash
ip=$1
mkdir nmap 2>/dev/null
nmap -sC -sV -oA nmap/comm-tcp $ip &>/dev/null &
nmap -p- -sV $ip > nmap/all-tcp &
nmap -sU $ip > nmap/comm-udp &
nmap -p- -sU $ip > nmap/all-udp &
